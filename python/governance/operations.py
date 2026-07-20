"""Chapter 8 production-operations patterns for governed agents.

These are dependency-free lab seams, not replacements for a durable control
plane, Kubernetes, OpenTelemetry, or the toolkit's agent-sre primitives.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Awaitable, Callable, Mapping

from .audit import AuditDecision, InMemoryAuditStore, record_operational_event
from .pipeline import PolicyAttachmentPoint
from .policy_engine import PolicyRegistry


class FailMode(str, Enum):
    FAIL_CLOSED = "fail_closed"
    FAIL_OPEN = "fail_open"


class PolicyChannel(str, Enum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True)
class FailModeConfig:
    modes: tuple[tuple[PolicyAttachmentPoint, FailMode], ...]

    def __post_init__(self) -> None:
        configured = dict(self.modes)
        if set(configured) != set(PolicyAttachmentPoint):
            raise ValueError("A fail mode is required for every attachment point")
        for point in (PolicyAttachmentPoint.PRE_INPUT, PolicyAttachmentPoint.PRE_TOOL):
            if configured[point] is not FailMode.FAIL_CLOSED:
                raise ValueError(f"{point.value} is security-critical and must fail closed")

    def for_point(self, point: PolicyAttachmentPoint) -> FailMode:
        return dict(self.modes)[point]


@dataclass(frozen=True)
class GovernanceSlo:
    maximum_latency_ms: tuple[tuple[PolicyAttachmentPoint, float], ...]
    availability_target: float = 0.999

    def __post_init__(self) -> None:
        budgets = dict(self.maximum_latency_ms)
        if set(budgets) != set(PolicyAttachmentPoint):
            raise ValueError("A latency budget is required for every attachment point")
        if any(value <= 0 for value in budgets.values()):
            raise ValueError("Latency budgets must be positive")
        if not 0 < self.availability_target <= 1:
            raise ValueError("Availability target must be between zero and one")

    def budget_for(self, point: PolicyAttachmentPoint) -> float:
        return dict(self.maximum_latency_ms)[point]


@dataclass(frozen=True)
class DeploymentTopology:
    environment: str
    policy_registry_url: str
    mesh_sidecar_url: str
    audit_sink_name: str
    rust_library_path: str
    required_components: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class HealthResult:
    component: str
    status: HealthStatus
    reason: str


@dataclass(frozen=True)
class ActivationRecord:
    rule_set_name: str
    source_channel: PolicyChannel
    target_channel: PolicyChannel
    previous_version: str | None
    activated_version: str
    correlation_id: str
    timestamp_utc: datetime


class FileVersionHistoryStore:
    """Thread-safe JSONL lab history that survives local process restarts.

    A production store needs transactions, multi-replica locking, encryption,
    retention, backups, access control, and independently protected evidence.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, record: ActivationRecord) -> None:
        payload = {
            "rule_set_name": record.rule_set_name,
            "source_channel": record.source_channel.value,
            "target_channel": record.target_channel.value,
            "previous_version": record.previous_version,
            "activated_version": record.activated_version,
            "correlation_id": record.correlation_id,
            "timestamp_utc": record.timestamp_utc.isoformat(),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._lock:
            descriptor = os.open(
                self._path,
                os.O_APPEND | os.O_CREAT | os.O_WRONLY
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise OSError("activation history must be a regular file")
                os.fchmod(descriptor, 0o600)
                payload_bytes = (encoded + "\n").encode()
                written = 0
                while written < len(payload_bytes):
                    count = os.write(descriptor, payload_bytes[written:])
                    if count <= 0:
                        raise OSError("activation history write made no progress")
                    written += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def records_for(self, rule_set_name: str) -> tuple[ActivationRecord, ...]:
        if not self._path.exists():
            return ()
        records: list[ActivationRecord] = []
        with self._lock:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            value = json.loads(line)
            if value["rule_set_name"] != rule_set_name:
                continue
            records.append(ActivationRecord(
                rule_set_name=value["rule_set_name"],
                source_channel=PolicyChannel(value["source_channel"]),
                target_channel=PolicyChannel(value["target_channel"]),
                previous_version=value["previous_version"],
                activated_version=value["activated_version"],
                correlation_id=value["correlation_id"],
                timestamp_utc=datetime.fromisoformat(value["timestamp_utc"]),
            ))
        return tuple(records)


class OperationalPolicyRegistry:
    """Adds channel activation and compare-and-swap to Chapter 3 registry."""

    def __init__(self, policies: PolicyRegistry) -> None:
        self._policies = policies
        self._active: dict[tuple[str, PolicyChannel], str] = {}
        self._generation = 0
        self._lock = threading.Lock()

    def require_registered(self, name: str, version: str) -> None:
        self._policies.load(name, version)

    def active_version(self, name: str, channel: PolicyChannel) -> str | None:
        with self._lock:
            return self._active.get((name, channel))

    def compare_and_activate(
        self,
        name: str,
        channel: PolicyChannel,
        version: str,
        expected_current: str | None,
    ) -> int:
        self.require_registered(name, version)
        with self._lock:
            key = (name, channel)
            actual = self._active.get(key)
            if actual != expected_current:
                raise RuntimeError(
                    f"Active version changed: expected {expected_current}, found {actual}"
                )
            self._active[key] = version
            self._generation += 1
            return self._generation

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation


class PolicyVersionResolver:
    def __init__(self, registry: OperationalPolicyRegistry) -> None:
        self._registry = registry
        self._cache: dict[tuple[str, PolicyChannel], tuple[int, str | None]] = {}

    def resolve(self, name: str, channel: PolicyChannel) -> str | None:
        key = (name, channel)
        generation = self._registry.generation
        cached = self._cache.get(key)
        if cached is not None and cached[0] == generation:
            return cached[1]
        version = self._registry.active_version(name, channel)
        self._cache[key] = (generation, version)
        return version

    def invalidate(self) -> None:
        self._cache.clear()


class PolicyPromotionPipeline:
    _allowed = {
        (PolicyChannel.DEV, PolicyChannel.STAGING),
        (PolicyChannel.STAGING, PolicyChannel.PROD),
    }

    def __init__(
        self,
        registry: OperationalPolicyRegistry,
        history: FileVersionHistoryStore,
        audit: InMemoryAuditStore,
        resolver: PolicyVersionResolver,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._history = history
        self._audit = audit
        self._resolver = resolver
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def promote(
        self,
        name: str,
        version: str,
        source: PolicyChannel,
        target: PolicyChannel,
        correlation_id: str,
    ) -> ActivationRecord:
        previous = self._registry.active_version(name, target)
        metadata = (
            ("source", source.value),
            ("target", target.value),
            ("previous", previous or "none"),
            ("version", version),
        )
        try:
            if (source, target) not in self._allowed:
                raise ValueError("Policies must move dev -> staging -> prod")
            self._registry.require_registered(name, version)
            if source is PolicyChannel.STAGING:
                staged = self._registry.active_version(name, PolicyChannel.STAGING)
                if staged != version:
                    raise PermissionError(
                        "Production promotion requires the same staged version"
                    )
            self._registry.compare_and_activate(name, target, version, previous)
            self._resolver.invalidate()
            record = ActivationRecord(
                name, source, target, previous, version, correlation_id, self._clock()
            )
            self._history.append(record)
        except Exception as exc:
            record_operational_event(
                self._audit,
                correlation_id=correlation_id,
                trace_id=None,
                event_name="policy_promotion_attempt",
                decision=AuditDecision.DENY,
                principal_id="policy-pipeline",
                agent_id="governance-control-plane",
                reason=f"Promotion rejected safely: {type(exc).__name__}",
                metadata=metadata,
            )
            raise
        record_operational_event(
            self._audit,
            correlation_id=correlation_id,
            trace_id=None,
            event_name="policy_promotion_attempt",
            decision=AuditDecision.ALLOW,
            principal_id="policy-pipeline",
            agent_id="governance-control-plane",
            reason=f"Promoted {name} from {source.value} to {target.value}",
            metadata=metadata,
        )
        return record


class RollbackController:
    def __init__(
        self,
        registry: OperationalPolicyRegistry,
        history: FileVersionHistoryStore,
        audit: InMemoryAuditStore,
        resolver: PolicyVersionResolver,
    ) -> None:
        self._registry = registry
        self._history = history
        self._audit = audit
        self._resolver = resolver

    def rollback(
        self,
        name: str,
        channel: PolicyChannel,
        expected_bad_version: str,
        correlation_id: str,
    ) -> str:
        current = self._registry.active_version(name, channel)
        previous: str | None = None
        try:
            if current != expected_bad_version:
                raise RuntimeError("Rollback refused because active state already changed")
            records = [
                record for record in self._history.records_for(name)
                if record.target_channel is channel
                and record.activated_version == current
            ]
            if not records or records[-1].previous_version is None:
                raise RuntimeError("No previous version available for rollback")
            previous = records[-1].previous_version
            self._registry.require_registered(name, previous)
            self._registry.compare_and_activate(name, channel, previous, current)
            self._resolver.invalidate()
            rollback_record = ActivationRecord(
                name,
                channel,
                channel,
                current,
                previous,
                correlation_id,
                datetime.now(timezone.utc),
            )
            self._history.append(rollback_record)
        except Exception as exc:
            record_operational_event(
                self._audit,
                correlation_id=correlation_id,
                trace_id=None,
                event_name="policy_rollback_attempt",
                decision=AuditDecision.DENY,
                principal_id="incident-controller",
                agent_id="governance-control-plane",
                reason=f"Rollback rejected safely: {type(exc).__name__}",
                metadata=(("active", current or "none"),
                          ("reported_bad", expected_bad_version)),
            )
            raise
        record_operational_event(
            self._audit,
            correlation_id=correlation_id,
            trace_id=None,
            event_name="policy_rollback_attempt",
            decision=AuditDecision.ALLOW,
            principal_id="incident-controller",
            agent_id="governance-control-plane",
            reason=f"Rolled back {name}@{current} to {previous}",
            metadata=(("active", current or "none"),
                      ("restored", previous)),
        )
        return previous


@dataclass(frozen=True)
class DriftBaseline:
    rule_set_name: str
    channel: PolicyChannel
    approved_version: str
    approved_attachment_points: frozenset[PolicyAttachmentPoint]


@dataclass(frozen=True)
class DriftFinding:
    drifted: bool
    reasons: tuple[str, ...]


class PolicyDriftDetector:
    def __init__(self, registry: OperationalPolicyRegistry) -> None:
        self._registry = registry

    def detect(
        self,
        baseline: DriftBaseline,
        actual_attachments: frozenset[PolicyAttachmentPoint],
    ) -> DriftFinding:
        reasons: list[str] = []
        actual = self._registry.active_version(
            baseline.rule_set_name, baseline.channel
        )
        if actual != baseline.approved_version:
            reasons.append(
                f"Version drift: approved {baseline.approved_version}, active {actual}"
            )
        if actual_attachments != baseline.approved_attachment_points:
            reasons.append("Attachment-point drift")
        return DriftFinding(bool(reasons), tuple(reasons))


class GovernanceHealthProbe:
    def __init__(self, checks: Mapping[str, Callable[[], bool]]) -> None:
        self._checks = dict(checks)

    def check(self) -> tuple[HealthResult, ...]:
        results: list[HealthResult] = []
        for name, check in sorted(self._checks.items()):
            try:
                healthy = bool(check())
                results.append(HealthResult(
                    name,
                    HealthStatus.HEALTHY if healthy else HealthStatus.UNHEALTHY,
                    "ready" if healthy else "required state unavailable",
                ))
            except Exception as exc:
                results.append(HealthResult(
                    name, HealthStatus.UNHEALTHY,
                    f"probe failed safely: {type(exc).__name__}",
                ))
        return tuple(results)

    def ready(self) -> bool:
        return all(result.status is HealthStatus.HEALTHY for result in self.check())


class LatencyBudgetEnforcer:
    def __init__(self, slo: GovernanceSlo, fail_modes: FailModeConfig) -> None:
        self._slo = slo
        self._fail_modes = fail_modes

    async def execute(
        self,
        point: PolicyAttachmentPoint,
        operation: Callable[[], Awaitable[object]],
    ) -> object:
        started = time.perf_counter()
        result = await operation()
        elapsed_ms = (time.perf_counter() - started) * 1000
        if elapsed_ms > self._slo.budget_for(point):
            if self._fail_modes.for_point(point) is FailMode.FAIL_CLOSED:
                raise TimeoutError(
                    f"Latency budget exceeded at {point.value}; failed closed"
                )
        return result


@dataclass(frozen=True)
class IncidentTrigger:
    incident_key: str
    rule_set_name: str
    channel: PolicyChannel
    observed_version: str
    correlation_id: str


class PolicyIncidentAdapter:
    """Deduplicate incident actions and reject stale rollback triggers."""

    def __init__(self, rollback: RollbackController) -> None:
        self._rollback = rollback
        self._handled: set[str] = set()
        self._lock = threading.Lock()

    def handle(self, trigger: IncidentTrigger) -> str:
        with self._lock:
            if trigger.incident_key in self._handled:
                return "duplicate_ignored"
            self._handled.add(trigger.incident_key)
        try:
            return self._rollback.rollback(
                trigger.rule_set_name,
                trigger.channel,
                trigger.observed_version,
                trigger.correlation_id,
            )
        except Exception:
            # Permit a corrected/retried incident only after explicit new key.
            raise


def default_fail_modes() -> FailModeConfig:
    return FailModeConfig((
        (PolicyAttachmentPoint.PRE_INPUT, FailMode.FAIL_CLOSED),
        (PolicyAttachmentPoint.PRE_TOOL, FailMode.FAIL_CLOSED),
        (PolicyAttachmentPoint.PRE_OUTPUT, FailMode.FAIL_CLOSED),
    ))


def default_slo() -> GovernanceSlo:
    return GovernanceSlo((
        (PolicyAttachmentPoint.PRE_INPUT, 50.0),
        (PolicyAttachmentPoint.PRE_TOOL, 25.0),
        (PolicyAttachmentPoint.PRE_OUTPUT, 75.0),
    ))
