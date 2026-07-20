"""Chapter 6: secure, cross-agent delegation primitives.

The module is intentionally independent of an LLM. Governance must be testable
without model calls, API keys, or network access.
"""

from __future__ import annotations

import base64
import json
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Callable, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class DelegationScope(str, Enum):
    READ_REPOSITORY = "read_repository"
    CREATE_PATCH = "create_patch"
    RUN_APPROVED_TESTS = "run_approved_tests"


class WorkflowPhase(str, Enum):
    INTAKE = "intake"
    ANALYSIS = "analysis"
    PATCH_CREATION = "patch_creation"
    TESTING = "testing"
    HUMAN_REVIEW = "human_review"
    COMPLETION = "completion"


class HandoffStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    EXPIRED = "expired"
    DENIED = "denied"


@dataclass(frozen=True)
class MeshAgentIdentity:
    agent_id: str
    framework: str
    public_key_fingerprint: str


@dataclass(frozen=True)
class AgentDelegationToken:
    token_id: str
    issuer_id: str
    subject_id: str
    audience_id: str
    scopes: tuple[DelegationScope, ...]
    phase: WorkflowPhase
    correlation_id: str
    repository_id: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    key_id: str
    delegation_depth: int


@dataclass(frozen=True)
class DelegationEnvelope:
    token_id: str
    issuer_id: str
    subject_id: str
    audience_id: str
    scopes: tuple[str, ...]
    phase: str
    correlation_id: str
    repository_id: str
    issued_at: str
    expires_at: str
    nonce: str
    key_id: str
    delegation_depth: int
    signature: str


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("delegation timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_claims(envelope: DelegationEnvelope) -> bytes:
    """Serialize every authorization claim in one documented field order.

    Python and Go use this exact compact JSON representation. Adding a new
    security claim requires adding it here and in the Go SignedClaims struct.
    """

    claims = {
        "token_id": envelope.token_id,
        "issuer_id": envelope.issuer_id,
        "subject_id": envelope.subject_id,
        "audience_id": envelope.audience_id,
        "scopes": sorted(envelope.scopes),
        "phase": envelope.phase,
        "correlation_id": envelope.correlation_id,
        "repository_id": envelope.repository_id,
        "issued_at": envelope.issued_at,
        "expires_at": envelope.expires_at,
        "nonce": envelope.nonce,
        "key_id": envelope.key_id,
        "delegation_depth": envelope.delegation_depth,
    }
    return json.dumps(claims, separators=(",", ":"), ensure_ascii=True).encode()


def unsigned_envelope(token: AgentDelegationToken) -> DelegationEnvelope:
    if token.expires_at <= token.issued_at:
        raise ValueError("delegation expiry must be after issue time")
    return DelegationEnvelope(
        token_id=token.token_id,
        issuer_id=token.issuer_id,
        subject_id=token.subject_id,
        audience_id=token.audience_id,
        scopes=tuple(sorted(scope.value for scope in token.scopes)),
        phase=token.phase.value,
        correlation_id=token.correlation_id,
        repository_id=token.repository_id,
        issued_at=_utc_text(token.issued_at),
        expires_at=_utc_text(token.expires_at),
        nonce=token.nonce,
        key_id=token.key_id,
        delegation_depth=token.delegation_depth,
        signature="",
    )


class TokenSigner:
    def __init__(self, private_key: Ed25519PrivateKey, issuer_id: str, key_id: str) -> None:
        if not key_id:
            raise ValueError("key ID is required")
        self._private_key = private_key
        self._issuer_id = issuer_id
        self._key_id = key_id

    def sign(self, token: AgentDelegationToken) -> DelegationEnvelope:
        if token.issuer_id != self._issuer_id:
            raise PermissionError("issuer does not own this signing key")
        if token.key_id != self._key_id:
            raise PermissionError("token is bound to another signing key")
        envelope = unsigned_envelope(token)
        signature = self._private_key.sign(_canonical_claims(envelope))
        return replace(
            envelope,
            signature=base64.b64encode(signature).decode("ascii"),
        )


class ReplayCache(Protocol):
    def consume(self, issuer_id: str, nonce: str, expires_at: datetime) -> bool:
        """Atomically return True only for the first valid use."""


class InMemoryReplayCache:
    """Thread-safe lab cache; production needs a shared atomic TTL store."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._seen: dict[tuple[str, str], datetime] = {}
        self._lock = threading.Lock()

    def consume(self, issuer_id: str, nonce: str, expires_at: datetime) -> bool:
        with self._lock:
            now = self._clock()
            self._seen = {key: exp for key, exp in self._seen.items() if exp > now}
            key = (issuer_id, nonce)
            if key in self._seen:
                return False
            self._seen[key] = expires_at
            return True


class TokenVerifier:
    def __init__(
        self,
        issuer_keys: Mapping[tuple[str, str], Ed25519PublicKey],
        expected_audience_id: str,
        expected_subject_id: str,
        replay_cache: ReplayCache,
        clock: Callable[[], datetime] | None = None,
        maximum_lifetime: timedelta = timedelta(minutes=10),
        clock_skew: timedelta = timedelta(seconds=30),
        maximum_delegation_depth: int = 1,
    ) -> None:
        self._issuer_keys = dict(issuer_keys)
        self._audience = expected_audience_id
        self._subject = expected_subject_id
        self._replay_cache = replay_cache
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._maximum_lifetime = maximum_lifetime
        self._clock_skew = clock_skew
        self._maximum_delegation_depth = maximum_delegation_depth

    def verify(self, envelope: DelegationEnvelope) -> AgentDelegationToken:
        required_text = (
            envelope.token_id, envelope.issuer_id, envelope.subject_id,
            envelope.audience_id, envelope.phase, envelope.correlation_id,
            envelope.repository_id, envelope.nonce, envelope.key_id,
        )
        if any(not value for value in required_text):
            raise PermissionError("delegation contains an empty required claim")
        if not envelope.scopes or len(set(envelope.scopes)) != len(envelope.scopes):
            raise PermissionError("delegation scopes must be non-empty and unique")
        if not 0 <= envelope.delegation_depth <= self._maximum_delegation_depth:
            raise PermissionError("delegation depth exceeds the permitted limit")

        key = self._issuer_keys.get((envelope.issuer_id, envelope.key_id))
        if key is None:
            raise PermissionError("untrusted delegation issuer")
        try:
            issued_at = datetime.fromisoformat(envelope.issued_at.replace("Z", "+00:00"))
            expires_at = datetime.fromisoformat(envelope.expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise PermissionError("invalid delegation timestamp") from exc

        now = self._clock()
        if issued_at > now + self._clock_skew:
            raise PermissionError("delegation was issued in the future")
        if expires_at <= now:
            raise PermissionError("delegation expired")
        if expires_at <= issued_at or expires_at - issued_at > self._maximum_lifetime:
            raise PermissionError("delegation lifetime is invalid")

        try:
            signature = base64.b64decode(envelope.signature, validate=True)
            key.verify(signature, _canonical_claims(envelope))
        except (InvalidSignature, ValueError) as exc:
            raise PermissionError("delegation signature is invalid") from exc

        if envelope.audience_id != self._audience:
            raise PermissionError("delegation audience mismatch")
        if envelope.subject_id != self._subject:
            raise PermissionError("delegation subject mismatch")

        if not self._replay_cache.consume(envelope.issuer_id, envelope.nonce, expires_at):
            raise PermissionError("delegation replay detected")

        try:
            scopes = tuple(DelegationScope(value) for value in envelope.scopes)
            phase = WorkflowPhase(envelope.phase)
        except ValueError as exc:
            raise PermissionError("unknown delegation scope or phase") from exc

        return AgentDelegationToken(
            token_id=envelope.token_id,
            issuer_id=envelope.issuer_id,
            subject_id=envelope.subject_id,
            audience_id=envelope.audience_id,
            scopes=scopes,
            phase=phase,
            correlation_id=envelope.correlation_id,
            repository_id=envelope.repository_id,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=envelope.nonce,
            key_id=envelope.key_id,
            delegation_depth=envelope.delegation_depth,
        )


@dataclass(frozen=True)
class SharedMemoryEntry:
    key: str
    serialized_value: bytes
    written_in_phase: WorkflowPhase
    readable_phases: frozenset[WorkflowPhase]

    @classmethod
    def from_json(
        cls,
        key: str,
        value: object,
        written_in_phase: WorkflowPhase,
        readable_phases: frozenset[WorkflowPhase],
    ) -> "SharedMemoryEntry":
        data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return cls(key, data, written_in_phase, readable_phases)

    def json_value(self) -> object:
        return json.loads(self.serialized_value)


class SharedMemorySegment:
    """Correlation-scoped memory with segment and entry phase gates."""

    def __init__(
        self,
        segment_id: str,
        correlation_id: str,
        write_phases: frozenset[WorkflowPhase],
        read_phases: frozenset[WorkflowPhase],
    ) -> None:
        self.segment_id = segment_id
        self.correlation_id = correlation_id
        self._write_phases = write_phases
        self._read_phases = read_phases
        self._entries: dict[str, SharedMemoryEntry] = {}
        self._lock = threading.Lock()

    def write(
        self,
        entry: SharedMemoryEntry,
        phase: WorkflowPhase,
        correlation_id: str,
    ) -> None:
        if correlation_id != self.correlation_id:
            raise PermissionError("shared-memory workflow mismatch")
        if phase not in self._write_phases or entry.written_in_phase is not phase:
            raise PermissionError("write denied for workflow phase")
        with self._lock:
            self._entries[entry.key] = entry

    def read(
        self,
        key: str,
        phase: WorkflowPhase,
        correlation_id: str,
    ) -> SharedMemoryEntry | None:
        if correlation_id != self.correlation_id:
            raise PermissionError("shared-memory workflow mismatch")
        if phase not in self._read_phases:
            raise PermissionError("segment read denied for workflow phase")
        with self._lock:
            entry = self._entries.get(key)
        if entry is not None and phase not in entry.readable_phases:
            raise PermissionError("entry read denied for workflow phase")
        return entry


@dataclass(frozen=True)
class HandoffSession:
    correlation_id: str
    token_id: str
    status: HandoffStatus
    created_at: datetime
    expires_at: datetime


class HandoffStore:
    """Strict state machine for a long-running delegation."""

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._sessions: dict[str, HandoffSession] = {}
        self._lock = threading.Lock()

    def create(self, correlation_id: str, token_id: str, timeout: timedelta) -> HandoffSession:
        if timeout <= timedelta(0) or timeout > timedelta(minutes=30):
            raise ValueError("handoff timeout must be between zero and 30 minutes")
        with self._lock:
            if correlation_id in self._sessions:
                raise ValueError("handoff already exists")
            now = self._clock()
            session = HandoffSession(
                correlation_id, token_id, HandoffStatus.PENDING, now, now + timeout
            )
            self._sessions[correlation_id] = session
            return session

    def get(self, correlation_id: str) -> HandoffSession | None:
        with self._lock:
            return self._sessions.get(correlation_id)

    def transition(self, correlation_id: str, target: HandoffStatus) -> HandoffSession:
        allowed = {
            HandoffStatus.PENDING: {HandoffStatus.ACTIVE, HandoffStatus.DENIED, HandoffStatus.EXPIRED},
            HandoffStatus.ACTIVE: {HandoffStatus.COMPLETED, HandoffStatus.DENIED, HandoffStatus.EXPIRED},
        }
        with self._lock:
            current = self._sessions[correlation_id]
            if self._clock() >= current.expires_at and target is not HandoffStatus.EXPIRED:
                raise PermissionError("expired handoff cannot transition")
            if target not in allowed.get(current.status, set()):
                raise PermissionError(f"invalid handoff transition: {current.status.value} -> {target.value}")
            updated = replace(current, status=target)
            self._sessions[correlation_id] = updated
            return updated

    def recover_or_expire(self, correlation_id: str) -> HandoffStatus:
        with self._lock:
            session = self._sessions.get(correlation_id)
            if session is None:
                return HandoffStatus.EXPIRED
            if self._clock() >= session.expires_at and session.status in {
                HandoffStatus.PENDING,
                HandoffStatus.ACTIVE,
            }:
                session = replace(session, status=HandoffStatus.EXPIRED)
                self._sessions[correlation_id] = session
            return session.status


def authorize_delegated_action(
    token: AgentDelegationToken,
    required_scope: DelegationScope,
    required_phase: WorkflowPhase,
    repository_id: str,
) -> None:
    if required_scope not in token.scopes:
        raise PermissionError(f"delegation lacks {required_scope.value} scope")
    if token.phase is not required_phase:
        raise PermissionError("delegation is not valid in this workflow phase")
    if token.repository_id != repository_id:
        raise PermissionError("delegation is bound to another repository")


def create_token(
    issuer_id: str,
    subject_id: str,
    audience_id: str,
    scopes: tuple[DelegationScope, ...],
    phase: WorkflowPhase,
    correlation_id: str,
    repository_id: str,
    now: datetime | None = None,
    key_id: str = "lab-key-1",
    delegation_depth: int = 0,
) -> AgentDelegationToken:
    required_text = (issuer_id, subject_id, audience_id, correlation_id, repository_id, key_id)
    if any(not value for value in required_text):
        raise ValueError("delegation claims must not be empty")
    if not scopes:
        raise ValueError("at least one delegation scope is required")
    if delegation_depth < 0:
        raise ValueError("delegation depth cannot be negative")
    issued = now or datetime.now(timezone.utc)
    return AgentDelegationToken(
        token_id=str(uuid.uuid4()),
        issuer_id=issuer_id,
        subject_id=subject_id,
        audience_id=audience_id,
        scopes=tuple(sorted(set(scopes), key=lambda item: item.value)),
        phase=phase,
        correlation_id=correlation_id,
        repository_id=repository_id,
        issued_at=issued,
        expires_at=issued + timedelta(minutes=5),
        nonce=str(uuid.uuid4()),
        key_id=key_id,
        delegation_depth=delegation_depth,
    )
