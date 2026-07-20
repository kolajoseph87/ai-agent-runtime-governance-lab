package mesh

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Deny is deliberately the zero value. Uninitialized verdicts must not allow.
type MeshVerdict int

const (
	MeshDeny MeshVerdict = iota
	MeshAllow
)

type EnforcementPoint int

const (
	MeshIngress EnforcementPoint = iota
	MeshEgress
)

type DelegationEnvelope struct {
	TokenID         string            `json:"token_id"`
	IssuerID        string            `json:"issuer_id"`
	SubjectID       string            `json:"subject_id"`
	AudienceID      string            `json:"audience_id"`
	Scopes          []string          `json:"scopes"`
	Phase           string            `json:"phase"`
	CorrelationID   string            `json:"correlation_id"`
	RepositoryID    string            `json:"repository_id"`
	IssuedAt        string            `json:"issued_at"`
	ExpiresAt       string            `json:"expires_at"`
	Nonce           string            `json:"nonce"`
	KeyID           string            `json:"key_id"`
	DelegationDepth int               `json:"delegation_depth"`
	Signature       string            `json:"signature"`
	Headers         map[string]string `json:"headers,omitempty"`
}

// signedClaims order must match governance/delegation.py::_canonical_claims.
type signedClaims struct {
	TokenID         string   `json:"token_id"`
	IssuerID        string   `json:"issuer_id"`
	SubjectID       string   `json:"subject_id"`
	AudienceID      string   `json:"audience_id"`
	Scopes          []string `json:"scopes"`
	Phase           string   `json:"phase"`
	CorrelationID   string   `json:"correlation_id"`
	RepositoryID    string   `json:"repository_id"`
	IssuedAt        string   `json:"issued_at"`
	ExpiresAt       string   `json:"expires_at"`
	Nonce           string   `json:"nonce"`
	KeyID           string   `json:"key_id"`
	DelegationDepth int      `json:"delegation_depth"`
}

func canonicalClaims(env DelegationEnvelope) ([]byte, error) {
	scopes := append([]string(nil), env.Scopes...)
	sort.Strings(scopes)
	return json.Marshal(signedClaims{
		TokenID: env.TokenID, IssuerID: env.IssuerID,
		SubjectID: env.SubjectID, AudienceID: env.AudienceID,
		Scopes: scopes, Phase: env.Phase, CorrelationID: env.CorrelationID,
		RepositoryID: env.RepositoryID, IssuedAt: env.IssuedAt,
		ExpiresAt: env.ExpiresAt, Nonce: env.Nonce,
		KeyID: env.KeyID, DelegationDepth: env.DelegationDepth,
	})
}

type ReplayCache interface {
	Consume(issuer, nonce string, expiresAt time.Time, now time.Time) bool
}

type MemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (c *MemoryReplayCache) Consume(issuer, nonce string, expiresAt, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = make(map[string]time.Time)
	}
	for key, expiry := range c.seen {
		if !expiry.After(now) {
			delete(c.seen, key)
		}
	}
	key := issuer + "\x00" + nonce
	if _, exists := c.seen[key]; exists {
		return false
	}
	c.seen[key] = expiresAt
	return true
}

type TokenValidator struct {
	IssuerPublicKeys       map[string]ed25519.PublicKey
	ExpectedAudienceID     string
	ExpectedSubjectID      string
	Replay                 ReplayCache
	Now                    func() time.Time
	MaximumLifetime        time.Duration
	MaximumDelegationDepth int
}

func (v TokenValidator) Validate(env DelegationEnvelope) error {
	required := []string{env.TokenID, env.IssuerID, env.SubjectID, env.AudienceID,
		env.Phase, env.CorrelationID, env.RepositoryID, env.Nonce, env.KeyID, env.Signature}
	for _, value := range required {
		if strings.TrimSpace(value) == "" {
			return errors.New("empty required delegation claim")
		}
	}
	if len(env.Scopes) == 0 {
		return errors.New("delegation requires at least one scope")
	}
	seenScope := make(map[string]bool, len(env.Scopes))
	for _, scope := range env.Scopes {
		if strings.TrimSpace(scope) == "" || seenScope[scope] {
			return errors.New("delegation scopes must be non-empty and unique")
		}
		seenScope[scope] = true
	}
	maximumDepth := v.MaximumDelegationDepth
	if maximumDepth <= 0 {
		maximumDepth = 1
	}
	if env.DelegationDepth < 0 || env.DelegationDepth > maximumDepth {
		return errors.New("delegation depth exceeds permitted limit")
	}
	publicKey, trusted := v.IssuerPublicKeys[env.IssuerID+"\x00"+env.KeyID]
	if !trusted {
		return errors.New("untrusted issuer")
	}
	issued, err := time.Parse(time.RFC3339, env.IssuedAt)
	if err != nil {
		return errors.New("invalid issued_at")
	}
	expires, err := time.Parse(time.RFC3339, env.ExpiresAt)
	if err != nil {
		return errors.New("invalid expires_at")
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	maximum := 10 * time.Minute
	if v.MaximumLifetime > 0 {
		maximum = v.MaximumLifetime
	}
	if issued.After(now.Add(30*time.Second)) || !expires.After(now) ||
		!expires.After(issued) || expires.Sub(issued) > maximum {
		return errors.New("invalid token lifetime")
	}
	payload, err := canonicalClaims(env)
	if err != nil {
		return errors.New("cannot canonicalize claims")
	}
	signature, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("invalid signature")
	}
	if env.AudienceID != v.ExpectedAudienceID || env.SubjectID != v.ExpectedSubjectID {
		return errors.New("audience or subject mismatch")
	}
	if v.Replay == nil || !v.Replay.Consume(env.IssuerID, env.Nonce, expires, now) {
		return errors.New("replayed token or unavailable replay protection")
	}
	return nil
}

type MeshPolicy struct {
	Name           string
	Point          EnforcementPoint
	AllowedIssuers map[string]bool
	AllowedScopes  map[string]bool
	DeniedPhases   map[string]bool
	Repositories   map[string]bool
}

type Guard struct {
	Point     EnforcementPoint
	Validator TokenValidator
	Policies  []MeshPolicy
}

func (g Guard) Evaluate(env DelegationEnvelope) (MeshVerdict, string) {
	if err := g.Validator.Validate(env); err != nil {
		return MeshDeny, err.Error()
	}
	for _, policy := range g.Policies {
		if policy.Point != g.Point {
			continue
		}
		if !policy.AllowedIssuers[env.IssuerID] {
			return MeshDeny, "issuer denied by mesh policy"
		}
		if policy.DeniedPhases[env.Phase] {
			return MeshDeny, "workflow phase denied by mesh policy"
		}
		if !policy.Repositories[env.RepositoryID] {
			return MeshDeny, "repository denied by mesh policy"
		}
		for _, scope := range env.Scopes {
			if !policy.AllowedScopes[scope] {
				return MeshDeny, "scope denied by mesh policy"
			}
		}
		return MeshAllow, "signed delegation satisfies mesh policy"
	}
	return MeshDeny, "no matching mesh policy"
}

type Server struct {
	Ingress Guard
}

func (s Server) ready() (bool, string) {
	validator := s.Ingress.Validator
	if strings.TrimSpace(validator.ExpectedAudienceID) == "" ||
		strings.TrimSpace(validator.ExpectedSubjectID) == "" {
		return false, "expected mesh identity is not configured"
	}
	if len(validator.IssuerPublicKeys) == 0 {
		return false, "trusted issuer keys are unavailable"
	}
	if validator.Replay == nil {
		return false, "replay protection is unavailable"
	}
	if len(s.Ingress.Policies) == 0 {
		return false, "mesh policies are unavailable"
	}
	return true, "ready"
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "reason": "GET required"})
			return
		}
		ready, reason := s.ready()
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "unhealthy", "reason": reason})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "reason": reason})
	})
	mux.HandleFunc("/v1/delegate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"verdict": "deny", "reason": "POST required"})
			return
		}
		var env DelegationEnvelope
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&env); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"verdict": "deny", "reason": "invalid envelope"})
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"verdict": "deny", "reason": "trailing JSON denied"})
			return
		}
		verdict, reason := s.Ingress.Evaluate(env)
		if verdict != MeshAllow {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{"verdict": "deny", "reason": reason})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"verdict": "allow", "reason": reason})
	})
	return mux
}
