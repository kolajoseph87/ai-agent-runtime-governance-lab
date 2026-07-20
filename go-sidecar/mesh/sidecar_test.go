package mesh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func fixture(t *testing.T) (DelegationEnvelope, Guard, ed25519.PrivateKey) {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	env := DelegationEnvelope{
		TokenID: "token-1", IssuerID: "python-security-analyzer",
		SubjectID: "dotnet-code-change-agent", AudienceID: "dotnet-code-change-agent",
		Scopes: []string{"create_patch"}, Phase: "patch_creation",
		CorrelationID: "corr-4821", RepositoryID: "payments-api",
		IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339),
		Nonce: "nonce-1",
		KeyID: "lab-key-1", DelegationDepth: 0,
	}
	payload, _ := canonicalClaims(env)
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	validator := TokenValidator{
		IssuerPublicKeys:   map[string]ed25519.PublicKey{env.IssuerID + "\x00" + env.KeyID: pub},
		ExpectedAudienceID: env.AudienceID, ExpectedSubjectID: env.SubjectID,
		Replay: &MemoryReplayCache{}, Now: func() time.Time { return now },
	}
	policy := MeshPolicy{
		Name: "secure-coding-handoff", Point: MeshIngress,
		AllowedIssuers: map[string]bool{env.IssuerID: true},
		AllowedScopes:  map[string]bool{"create_patch": true},
		DeniedPhases:   map[string]bool{"completion": true},
		Repositories:   map[string]bool{"payments-api": true},
	}
	return env, Guard{Point: MeshIngress, Validator: validator, Policies: []MeshPolicy{policy}}, privateKey
}

func TestIngressAllowsValidDelegation(t *testing.T) {
	env, guard, _ := fixture(t)
	if verdict, reason := guard.Evaluate(env); verdict != MeshAllow {
		t.Fatalf("expected allow, got %v: %s", verdict, reason)
	}
}

func TestIngressDeniesTamperedScope(t *testing.T) {
	env, guard, _ := fixture(t)
	env.Scopes = []string{"deploy_production"}
	if verdict, _ := guard.Evaluate(env); verdict != MeshDeny {
		t.Fatal("tampered signed scope must be denied")
	}
}

func TestIngressDeniesReplay(t *testing.T) {
	env, guard, _ := fixture(t)
	if verdict, _ := guard.Evaluate(env); verdict != MeshAllow {
		t.Fatal("first use should be allowed")
	}
	if verdict, _ := guard.Evaluate(env); verdict != MeshDeny {
		t.Fatal("second use must be denied")
	}
}

func TestIngressDeniesMissingPolicy(t *testing.T) {
	env, guard, _ := fixture(t)
	guard.Policies = nil
	if verdict, _ := guard.Evaluate(env); verdict != MeshDeny {
		t.Fatal("missing policy must fail closed")
	}
}

func TestIngressDeniedPhase(t *testing.T) {
	env, guard, privateKey := fixture(t)
	env.Phase = "completion"
	payload, _ := canonicalClaims(env)
	// Keep the token cryptographically valid so this exercises the phase policy.
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if verdict, _ := guard.Evaluate(env); verdict != MeshDeny {
		t.Fatal("denied phase must not pass")
	}
}

func TestIngressDeniesEmptyScopes(t *testing.T) {
	env, guard, privateKey := fixture(t)
	env.Scopes = nil
	payload, _ := canonicalClaims(env)
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if verdict, _ := guard.Evaluate(env); verdict != MeshDeny {
		t.Fatal("empty scopes must not pass vacuously")
	}
}

func TestIngressDeniesExcessiveDelegationDepth(t *testing.T) {
	env, guard, privateKey := fixture(t)
	env.DelegationDepth = 2
	payload, _ := canonicalClaims(env)
	env.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	if verdict, _ := guard.Evaluate(env); verdict != MeshDeny {
		t.Fatal("excessive delegation depth must be denied")
	}
}
