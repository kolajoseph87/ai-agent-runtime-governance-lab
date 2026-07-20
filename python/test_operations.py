import asyncio
import stat

import pytest

from governance.audit import InMemoryAuditStore
from governance.coding_policy_set import SecureCodingPolicySet
from governance.operations import (
    DriftBaseline,
    FailMode,
    FailModeConfig,
    FileVersionHistoryStore,
    GovernanceHealthProbe,
    GovernanceSlo,
    IncidentTrigger,
    LatencyBudgetEnforcer,
    OperationalPolicyRegistry,
    PolicyChannel,
    PolicyDriftDetector,
    PolicyIncidentAdapter,
    PolicyPromotionPipeline,
    PolicyVersionResolver,
    RollbackController,
    default_fail_modes,
)
from governance.pipeline import PolicyAttachmentPoint
from governance.policy_engine import PolicyRegistry


def _components(tmp_path):
    policies = PolicyRegistry()
    SecureCodingPolicySet.register_all(policies)
    registry = OperationalPolicyRegistry(policies)
    history = FileVersionHistoryStore(tmp_path / "activation-history.jsonl")
    audit = InMemoryAuditStore()
    resolver = PolicyVersionResolver(registry)
    promotion = PolicyPromotionPipeline(registry, history, audit, resolver)
    return registry, history, audit, resolver, promotion


def _seed_dev(registry, name="secure-coding-input", version="1.0.0"):
    registry.compare_and_activate(name, PolicyChannel.DEV, version, None)


def test_critical_boundaries_cannot_fail_open():
    for critical in (PolicyAttachmentPoint.PRE_INPUT, PolicyAttachmentPoint.PRE_TOOL):
        modes = dict(default_fail_modes().modes)
        modes[critical] = FailMode.FAIL_OPEN
        with pytest.raises(ValueError, match="must fail closed"):
            FailModeConfig(tuple(modes.items()))


def test_output_fail_open_requires_explicit_configuration():
    assert default_fail_modes().for_point(PolicyAttachmentPoint.PRE_OUTPUT) is FailMode.FAIL_CLOSED
    modes = dict(default_fail_modes().modes)
    modes[PolicyAttachmentPoint.PRE_OUTPUT] = FailMode.FAIL_OPEN
    config = FailModeConfig(tuple(modes.items()))
    assert config.for_point(PolicyAttachmentPoint.PRE_OUTPUT) is FailMode.FAIL_OPEN


def test_promotion_must_follow_dev_staging_prod(tmp_path):
    registry, _, _, _, promotion = _components(tmp_path)
    _seed_dev(registry)
    with pytest.raises(ValueError, match="dev -> staging -> prod"):
        promotion.promote(
            "secure-coding-input", "1.0.0", PolicyChannel.DEV,
            PolicyChannel.PROD, "corr-skip"
        )


def test_production_requires_the_exact_staged_version(tmp_path):
    registry, _, audit, resolver, promotion = _components(tmp_path)
    _seed_dev(registry)
    promotion.promote(
        "secure-coding-input", "1.0.0", PolicyChannel.DEV,
        PolicyChannel.STAGING, "corr-stage"
    )
    with pytest.raises(PermissionError, match="same staged version"):
        promotion.promote(
            "secure-coding-input", "1.1.0", PolicyChannel.STAGING,
            PolicyChannel.PROD, "corr-wrong-version"
        )
    assert resolver.resolve("secure-coding-input", PolicyChannel.PROD) is None
    records = audit.snapshot()
    assert len(records) == 2
    assert records[-1].decision.value == "DENY"
    assert "PermissionError" in records[-1].reason


def test_rejected_promotion_does_not_create_activation_history(tmp_path):
    registry, history, audit, _, promotion = _components(tmp_path)
    _seed_dev(registry)
    with pytest.raises(ValueError, match="dev -> staging -> prod"):
        promotion.promote(
            "secure-coding-input", "1.0.0", PolicyChannel.DEV,
            PolicyChannel.PROD, "corr-rejected"
        )
    assert history.records_for("secure-coding-input") == ()
    assert audit.snapshot()[-1].decision.value == "DENY"


def test_activation_history_survives_a_new_store_instance(tmp_path):
    registry, _, _, _, promotion = _components(tmp_path)
    _seed_dev(registry)
    promotion.promote(
        "secure-coding-input", "1.0.0", PolicyChannel.DEV,
        PolicyChannel.STAGING, "corr-persist"
    )
    reopened = FileVersionHistoryStore(tmp_path / "activation-history.jsonl")
    records = reopened.records_for("secure-coding-input")
    assert len(records) == 1
    assert records[0].activated_version == "1.0.0"


def test_activation_history_file_permissions_are_restricted(tmp_path):
    registry, history, _, _, promotion = _components(tmp_path)
    _seed_dev(registry)
    promotion.promote(
        "secure-coding-input", "1.0.0", PolicyChannel.DEV,
        PolicyChannel.STAGING, "corr-permissions"
    )
    mode = stat.S_IMODE((tmp_path / "activation-history.jsonl").stat().st_mode)
    assert mode == 0o600


def test_resolver_refreshes_after_activation(tmp_path):
    registry, _, _, resolver, promotion = _components(tmp_path)
    assert resolver.resolve("secure-coding-input", PolicyChannel.STAGING) is None
    _seed_dev(registry)
    promotion.promote(
        "secure-coding-input", "1.0.0", PolicyChannel.DEV,
        PolicyChannel.STAGING, "corr-cache"
    )
    assert resolver.resolve("secure-coding-input", PolicyChannel.STAGING) == "1.0.0"


def test_rollback_restores_previous_and_rejects_stale_incident(tmp_path):
    registry, history, audit, resolver, promotion = _components(tmp_path)
    _seed_dev(registry)
    promotion.promote("secure-coding-input", "1.0.0", PolicyChannel.DEV,
                      PolicyChannel.STAGING, "corr-stage-one")
    registry.compare_and_activate("secure-coding-input", PolicyChannel.DEV, "1.1.0", "1.0.0")
    promotion.promote("secure-coding-input", "1.1.0", PolicyChannel.DEV,
                      PolicyChannel.STAGING, "corr-stage-two")
    rollback = RollbackController(registry, history, audit, resolver)
    assert rollback.rollback(
        "secure-coding-input", PolicyChannel.STAGING, "1.1.0", "corr-rollback"
    ) == "1.0.0"
    rollback_records = history.records_for("secure-coding-input")
    assert rollback_records[-1].previous_version == "1.1.0"
    assert rollback_records[-1].activated_version == "1.0.0"
    with pytest.raises(RuntimeError, match="active state already changed"):
        rollback.rollback(
            "secure-coding-input", PolicyChannel.STAGING, "1.1.0", "corr-stale"
        )
    assert audit.snapshot()[-1].decision.value == "DENY"


def test_incident_handler_deduplicates_the_same_incident(tmp_path):
    registry, history, audit, resolver, promotion = _components(tmp_path)
    _seed_dev(registry)
    promotion.promote("secure-coding-input", "1.0.0", PolicyChannel.DEV,
                      PolicyChannel.STAGING, "corr-stage-one")
    registry.compare_and_activate("secure-coding-input", PolicyChannel.DEV, "1.1.0", "1.0.0")
    promotion.promote("secure-coding-input", "1.1.0", PolicyChannel.DEV,
                      PolicyChannel.STAGING, "corr-stage-two")
    adapter = PolicyIncidentAdapter(
        RollbackController(registry, history, audit, resolver)
    )
    trigger = IncidentTrigger(
        "incident-42", "secure-coding-input", PolicyChannel.STAGING,
        "1.1.0", "corr-incident"
    )
    assert adapter.handle(trigger) == "1.0.0"
    assert adapter.handle(trigger) == "duplicate_ignored"


def test_drift_detector_checks_version_and_attachment_points(tmp_path):
    registry, _, _, _, _ = _components(tmp_path)
    _seed_dev(registry)
    detector = PolicyDriftDetector(registry)
    baseline = DriftBaseline(
        "secure-coding-input", PolicyChannel.DEV, "1.1.0",
        frozenset({PolicyAttachmentPoint.PRE_INPUT})
    )
    finding = detector.detect(
        baseline, frozenset({PolicyAttachmentPoint.PRE_INPUT,
                             PolicyAttachmentPoint.PRE_TOOL})
    )
    assert finding.drifted
    assert len(finding.reasons) == 2


def test_health_probe_returns_unhealthy_instead_of_throwing():
    def broken():
        raise RuntimeError("secret internal detail")

    probe = GovernanceHealthProbe({"registry": lambda: True, "sidecar": broken})
    results = probe.check()
    assert not probe.ready()
    assert any(item.component == "sidecar" and item.status.value == "unhealthy"
               for item in results)
    assert all("secret internal detail" not in item.reason for item in results)


def test_latency_budget_fails_closed_at_critical_boundary():
    slo = GovernanceSlo(tuple((point, 0.01) for point in PolicyAttachmentPoint))
    enforcer = LatencyBudgetEnforcer(slo, default_fail_modes())

    async def slow():
        await asyncio.sleep(0.002)
        return "late"

    with pytest.raises(TimeoutError, match="failed closed"):
        asyncio.run(enforcer.execute(PolicyAttachmentPoint.PRE_TOOL, slow))


def test_explicit_low_risk_output_fail_open_returns_late_result():
    slo = GovernanceSlo(tuple((point, 0.01) for point in PolicyAttachmentPoint))
    modes = dict(default_fail_modes().modes)
    modes[PolicyAttachmentPoint.PRE_OUTPUT] = FailMode.FAIL_OPEN
    enforcer = LatencyBudgetEnforcer(slo, FailModeConfig(tuple(modes.items())))

    async def slow():
        await asyncio.sleep(0.002)
        return "late but explicitly permitted"

    assert asyncio.run(enforcer.execute(PolicyAttachmentPoint.PRE_OUTPUT, slow)) == \
        "late but explicitly permitted"
