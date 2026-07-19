from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from control_audit import build_report, policy_configuration_snapshot
from governance.control_evidence import secure_coding_control_evidence
from governance.coverage import (
    ControlCoverageMatrix,
    ControlEvidence,
    ControlLayer,
    ControlPlacementValidator,
    CoverageStatus,
    OwaspAgenticRisk,
    OwaspGapAnalyzer,
)
from governance.pipeline import PolicyAttachmentPoint
from governance.policy_composition import create_policy_registry, create_versioned_pipeline
from governance.policy_engine import (
    ConditionKind,
    PolicyAction,
    PolicyCondition,
    PolicyRule,
    PolicyRuleSet,
    PolicyTraceAnnotation,
    PolicyVersion,
)


def finding(report, risk):
    return next(item for item in report.findings if item.risk is risk)


def test_real_lab_report_is_honest_about_verified_partial_and_external_controls():
    report = build_report()
    assert finding(report, OwaspAgenticRisk.T2).status is CoverageStatus.VERIFIED
    for risk in (OwaspAgenticRisk.T3, OwaspAgenticRisk.T4, OwaspAgenticRisk.T6,
                 OwaspAgenticRisk.T8, OwaspAgenticRisk.T9):
        assert finding(report, risk).status is CoverageStatus.PARTIAL
    for risk in (OwaspAgenticRisk.T1, OwaspAgenticRisk.T5,
                 OwaspAgenticRisk.T7, OwaspAgenticRisk.T10):
        assert finding(report, risk).status is CoverageStatus.EXTERNAL_REQUIRED


def test_attachment_without_evidence_does_not_create_coverage():
    pipeline = create_versioned_pipeline()
    report = OwaspGapAnalyzer(ControlCoverageMatrix()).analyze(
        (), pipeline.attachment_points, pipeline.configuration_snapshot()
    )
    assert finding(report, OwaspAgenticRisk.T2).status is CoverageStatus.MISSING


def test_untested_evidence_does_not_count_as_verified():
    item = secure_coding_control_evidence()[0]
    untested = ControlEvidence(
        item.control_id, item.capability, item.layer, True, False,
        item.implementation_reference, "", item.attachment_point,
    )
    report = OwaspGapAnalyzer(ControlCoverageMatrix()).analyze(
        (untested,), frozenset({PolicyAttachmentPoint.PRE_TOOL}), "snapshot"
    )
    assert item.capability in finding(report, OwaspAgenticRisk.T2).missing_capabilities


def test_wrong_attachment_does_not_satisfy_requirement():
    evidence = ControlEvidence(
        "wrong-place", "tool_allowlist", ControlLayer.RUNTIME, True, True,
        "x", "y", PolicyAttachmentPoint.PRE_INPUT,
    )
    report = OwaspGapAnalyzer(ControlCoverageMatrix()).analyze(
        (evidence,), frozenset(PolicyAttachmentPoint), "snapshot"
    )
    assert "tool_allowlist" in finding(report, OwaspAgenticRisk.T2).missing_capabilities


def test_policy_cannot_claim_non_runtime_risk():
    rules = PolicyRuleSet(
        "dishonest-policy", PolicyVersion(1, 0, 0), PolicyAttachmentPoint.PRE_INPUT,
        (PolicyRule("allow", 9999, PolicyCondition(ConditionKind.MATCH_ALL), PolicyAction.ALLOW),),
        (PolicyTraceAnnotation("T7", "model_alignment_evaluation", "Incorrect runtime claim"),),
    )
    errors = ControlPlacementValidator.validate_policy_annotations(rules, ControlCoverageMatrix())
    assert errors and "non-runtime" in errors[0]


def test_real_policy_annotations_validate():
    registry = create_policy_registry()
    matrix = ControlCoverageMatrix()
    for name in ("secure-coding-input", "secure-coding-tool", "secure-coding-output"):
        assert not ControlPlacementValidator.validate_policy_annotations(
            registry.load(name, "1.1.0"), matrix
        )


def test_report_and_matrix_are_immutable():
    report = build_report()
    with pytest.raises(FrozenInstanceError):
        report.matrix_version = "tampered"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        report.findings[0].status = CoverageStatus.VERIFIED  # type: ignore[misc]


def test_configuration_fingerprint_changes_when_policy_version_changes():
    assert build_report("1.0.0").configuration_fingerprint != build_report("1.1.0").configuration_fingerprint


def test_configuration_snapshot_contains_enforcement_rule_content():
    snapshot = policy_configuration_snapshot("1.1.0")
    serialized = repr(snapshot)
    assert "deny_ignore_previous_instructions" in serialized
    assert "ignore previous instructions" in serialized
    assert "deny" in serialized


def test_declared_evidence_references_existing_implementation_and_test():
    python_root = Path(__file__).parent
    for item in secure_coding_control_evidence():
        assert (python_root / item.implementation_reference).is_file()
        test_file, separator, test_name = item.test_reference.partition("::")
        assert separator and test_name.startswith("test_")
        source = (python_root / test_file).read_text(encoding="utf-8")
        assert f"def {test_name}(" in source
