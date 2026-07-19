"""Run the evidence-based Chapter 5 audit locally or in CI."""

import argparse
import json

from governance.control_evidence import secure_coding_control_evidence
from governance.coverage import (
    ControlCoverageMatrix,
    CoverageStatus,
    OwaspGapAnalyzer,
)
from governance.policy_composition import create_policy_registry, create_versioned_pipeline
from governance.rings import SECURE_CODING_ASSIGNMENTS


def policy_configuration_snapshot(policy_version: str) -> tuple:
    registry = create_policy_registry()
    snapshots = []
    for name in ("secure-coding-input", "secure-coding-tool", "secure-coding-output"):
        rule_set = registry.load(name, policy_version)
        rules = tuple(
            (
                rule.name,
                rule.priority,
                rule.condition.kind.value,
                getattr(rule.condition.value, "pattern", rule.condition.value),
                getattr(rule.condition.value, "flags", None),
                rule.action.value,
                rule.description,
            )
            for rule in rule_set.rules
        )
        annotations = tuple(
            (item.risk_id, item.capability, item.justification)
            for item in rule_set.annotations
        )
        snapshots.append((
            rule_set.name,
            str(rule_set.version),
            rule_set.attachment_point.value,
            rules,
            annotations,
        ))
    return tuple(snapshots)


def build_report(policy_version: str = "1.1.0"):
    pipeline = create_versioned_pipeline(policy_version)
    snapshot = {
        "policy_version": policy_version,
        "policy_rule_sets": policy_configuration_snapshot(policy_version),
        "pipeline": pipeline.configuration_snapshot(),
        "ring_assignments": tuple(
            sorted((name, int(value.ring)) for name, value in SECURE_CODING_ASSIGNMENTS.items())
        ),
    }
    return OwaspGapAnalyzer(ControlCoverageMatrix()).analyze(
        secure_coding_control_evidence(), pipeline.attachment_points, snapshot
    )


def report_as_dict(report) -> dict:
    return {
        "matrix_version": report.matrix_version,
        "configuration_fingerprint": report.configuration_fingerprint,
        "summary": {
            status.value: sum(1 for finding in report.findings if finding.status is status)
            for status in CoverageStatus
        },
        "findings": [
            {
                "risk": finding.risk.value,
                "name": finding.risk_name,
                "status": finding.status.value,
                "primary_layer": finding.primary_layer.value,
                "verified_capabilities": finding.verified_capabilities,
                "missing_capabilities": finding.missing_capabilities,
                "explanation": finding.explanation,
            }
            for finding in report.findings
        ],
        "false_confidence_flags": report.false_confidence_flags,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy-version", default="1.1.0")
    parser.add_argument(
        "--fail-on-partial", action="store_true",
        help="Production-style mode: return nonzero for partial runtime/identity/infrastructure coverage",
    )
    args = parser.parse_args()
    report = build_report(args.policy_version)
    print(json.dumps(report_as_dict(report), indent=2))
    if report.deployment_blocking_runtime_gaps:
        return 1
    if args.fail_on_partial and any(
        finding.status is CoverageStatus.PARTIAL for finding in report.findings
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
