"""Chapter 7 structured audit evidence and failure reconstruction.

The in-memory hash chain detects accidental or test-time modification. It is
not a substitute for signed, append-only production storage.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable

from .pipeline import (
    EvaluationOutcome,
    PolicyAttachmentPoint,
    PolicyEvaluationEvent,
)


_SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
)


def _safe_text(value: str, maximum: int) -> str:
    """Bound and redact free-form evidence before it becomes a log channel."""

    cleaned = value.replace("\r", "\\r").replace("\n", "\\n")
    for pattern in _SECRET_PATTERNS:
        cleaned = pattern.sub("[REDACTED]", cleaned)
    return cleaned[:maximum]


def _required_identifier(name: str, value: str, maximum: int = 256) -> str:
    if not value or len(value) > maximum:
        raise ValueError(f"{name} must contain 1 to {maximum} characters")
    return value


class AuditDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ERROR = "ERROR"


@dataclass(frozen=True)
class AuditEvent:
    correlation_id: str
    trace_id: str | None
    attachment_point: str
    policy_version: str
    policy_name: str
    decision: AuditDecision
    principal_id: str
    agent_id: str
    reason: str
    duration_ms: float
    metadata: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class AuditRecord:
    event_id: str
    sequence: int
    timestamp_utc: datetime
    correlation_id: str
    trace_id: str | None
    attachment_point: str
    policy_version: str
    policy_name: str
    decision: AuditDecision
    principal_id: str
    agent_id: str
    reason: str
    duration_ms: float
    metadata: tuple[tuple[str, str], ...]
    previous_hash: str
    record_hash: str


def _record_payload(record: AuditRecord) -> bytes:
    values = {
        "event_id": record.event_id,
        "sequence": record.sequence,
        "timestamp_utc": record.timestamp_utc.isoformat(),
        "correlation_id": record.correlation_id,
        "trace_id": record.trace_id,
        "attachment_point": record.attachment_point,
        "policy_version": record.policy_version,
        "policy_name": record.policy_name,
        "decision": record.decision.value,
        "principal_id": record.principal_id,
        "agent_id": record.agent_id,
        "reason": record.reason,
        "duration_ms": record.duration_ms,
        "metadata": list(record.metadata),
        "previous_hash": record.previous_hash,
    }
    return json.dumps(values, sort_keys=True, separators=(",", ":")).encode()


class InMemoryAuditStore:
    """Thread-safe append-only lab store with a SHA-256 integrity chain."""

    def __init__(
        self,
        clock: Callable[[], datetime] | None = None,
        event_id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._event_id_factory = event_id_factory or (lambda: str(uuid.uuid4()))
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def append(self, event: AuditEvent) -> AuditRecord:
        with self._lock:
            _required_identifier("correlation_id", event.correlation_id)
            _required_identifier("attachment_point", event.attachment_point)
            _required_identifier("policy_version", event.policy_version)
            _required_identifier("policy_name", event.policy_name)
            _required_identifier("principal_id", event.principal_id)
            _required_identifier("agent_id", event.agent_id)
            if event.trace_id is not None and len(event.trace_id) > 1024:
                raise ValueError("trace_id exceeds 1024 characters")
            if not math.isfinite(event.duration_ms) or event.duration_ms < 0:
                raise ValueError("duration_ms must be finite and non-negative")
            if len(event.metadata) > 32:
                raise ValueError("audit metadata exceeds 32 entries")

            now = self._clock()
            if now.tzinfo is None:
                raise ValueError("audit clock must return a timezone-aware timestamp")
            event_id = _required_identifier("event_id", self._event_id_factory())
            metadata = tuple(sorted(
                (_safe_text(key, 128), _safe_text(value, 512))
                for key, value in event.metadata
            ))
            previous_hash = self._records[-1].record_hash if self._records else "GENESIS"
            draft = AuditRecord(
                event_id=event_id,
                sequence=len(self._records) + 1,
                timestamp_utc=now.astimezone(timezone.utc),
                correlation_id=event.correlation_id,
                trace_id=event.trace_id,
                attachment_point=event.attachment_point,
                policy_version=event.policy_version,
                policy_name=event.policy_name,
                decision=event.decision,
                principal_id=event.principal_id,
                agent_id=event.agent_id,
                reason=_safe_text(event.reason, 2048),
                duration_ms=event.duration_ms,
                metadata=metadata,
                previous_hash=previous_hash,
                record_hash="",
            )
            digest = hashlib.sha256(_record_payload(draft)).hexdigest()
            record = replace(draft, record_hash=digest)
            self._records.append(record)
            return record

    def query_by_correlation(self, correlation_id: str) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(
                record for record in self._records
                if record.correlation_id == correlation_id
            )

    def snapshot(self) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def verify_integrity(self, records: Iterable[AuditRecord] | None = None) -> bool:
        candidate = tuple(records) if records is not None else self.snapshot()
        previous = "GENESIS"
        for expected_sequence, record in enumerate(candidate, start=1):
            if record.sequence != expected_sequence or record.previous_hash != previous:
                return False
            if hashlib.sha256(_record_payload(record)).hexdigest() != record.record_hash:
                return False
            previous = record.record_hash
        return True


class PipelineAuditObserver:
    """Translate pipeline events into stable structured audit evidence."""

    def __init__(self, store: InMemoryAuditStore, policy_version: str) -> None:
        self._store = store
        self._policy_version = policy_version

    def __call__(self, event: PolicyEvaluationEvent) -> None:
        decision = {
            EvaluationOutcome.ALLOW: AuditDecision.ALLOW,
            EvaluationOutcome.DENY: AuditDecision.DENY,
            EvaluationOutcome.ERROR: AuditDecision.ERROR,
        }[event.outcome]
        self._store.append(AuditEvent(
            correlation_id=event.correlation_id,
            trace_id=event.trace_id,
            attachment_point=event.attachment_point.value,
            policy_version=self._policy_version,
            policy_name=event.policy_name,
            decision=decision,
            principal_id=event.principal_id,
            agent_id=event.agent_id,
            reason=event.reason,
            duration_ms=event.duration_ms,
        ))


@dataclass(frozen=True)
class FailureClassification:
    category: str
    reason: str
    timeline: tuple[AuditRecord, ...]


class FailureAnalyzer:
    def __init__(self, store: InMemoryAuditStore) -> None:
        self._store = store

    def reconstruct_timeline(self, correlation_id: str) -> tuple[AuditRecord, ...]:
        return tuple(sorted(
            self._store.query_by_correlation(correlation_id),
            key=lambda record: (record.timestamp_utc, record.sequence),
        ))

    def classify(self, correlation_id: str) -> FailureClassification:
        timeline = self.reconstruct_timeline(correlation_id)
        if not timeline:
            return FailureClassification(
                "unknown", "No audit evidence was found", timeline
            )
        if any(record.decision is AuditDecision.ERROR for record in timeline):
            return FailureClassification(
                "runtime_exception",
                "A governance component timed out or raised an exception",
                timeline,
            )
        if any(record.decision is AuditDecision.DENY for record in timeline):
            return FailureClassification(
                "policy_denial", "A policy intentionally stopped progression", timeline
            )
        return FailureClassification(
            "control_path_allowed",
            "All recorded controls allowed; model/tool success requires separate events",
            timeline,
        )


def record_operational_event(
    store: InMemoryAuditStore,
    *,
    correlation_id: str,
    trace_id: str | None,
    event_name: str,
    decision: AuditDecision,
    principal_id: str,
    agent_id: str,
    reason: str,
    metadata: tuple[tuple[str, str], ...] = (),
) -> AuditRecord:
    """Record a sandbox, handoff, sidecar, model, or worker event safely."""

    return store.append(AuditEvent(
        correlation_id=correlation_id,
        trace_id=trace_id,
        attachment_point=event_name,
        policy_version="operational-event-v1",
        policy_name=event_name,
        decision=decision,
        principal_id=principal_id,
        agent_id=agent_id,
        reason=reason,
        duration_ms=0.0,
        metadata=metadata,
    ))
