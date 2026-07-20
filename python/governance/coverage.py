"""Evidence-based OWASP control placement and gap analysis for Chapter 5."""

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Iterable, Mapping

from .pipeline import PolicyAttachmentPoint
from .policy_engine import PolicyRuleSet


class OwaspAgenticRisk(str, Enum):
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"
    T4 = "T4"
    T5 = "T5"
    T6 = "T6"
    T7 = "T7"
    T8 = "T8"
    T9 = "T9"
    T10 = "T10"


class ControlLayer(str, Enum):
    RUNTIME = "runtime"
    FRAMEWORK = "framework"
    INFRASTRUCTURE = "infrastructure"
    IDENTITY = "identity"
    DATA = "data"
    HUMAN_PROCESS = "human_process"


class CoverageStatus(str, Enum):
    VERIFIED = "verified"
    PARTIAL = "partial"
    MISSING = "missing"
    EXTERNAL_REQUIRED = "external_required"


@dataclass(frozen=True)
class CapabilityRequirement:
    capability: str
    layer: ControlLayer
    attachment_point: PolicyAttachmentPoint | None = None


@dataclass(frozen=True)
class OwaspRiskCoverage:
    risk: OwaspAgenticRisk
    risk_name: str
    primary_layer: ControlLayer
    runtime_addressable: bool
    requirements: tuple[CapabilityRequirement, ...]
    secondary_layers: frozenset[ControlLayer] = frozenset()


@dataclass(frozen=True)
class ControlEvidence:
    control_id: str
    capability: str
    layer: ControlLayer
    implemented: bool
    tested: bool
    implementation_reference: str
    test_reference: str
    attachment_point: PolicyAttachmentPoint | None = None

    @property
    def verified(self) -> bool:
        return self.implemented and self.tested


@dataclass(frozen=True)
class RiskFinding:
    risk: OwaspAgenticRisk
    risk_name: str
    status: CoverageStatus
    primary_layer: ControlLayer
    verified_capabilities: tuple[str, ...]
    missing_capabilities: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class GapAnalysisReport:
    matrix_version: str
    configuration_fingerprint: str
    findings: tuple[RiskFinding, ...]
    false_confidence_flags: tuple[str, ...]

    @property
    def deployment_blocking_runtime_gaps(self) -> tuple[RiskFinding, ...]:
        return tuple(
            finding for finding in self.findings
            if finding.status is CoverageStatus.MISSING
            and finding.primary_layer in {
                ControlLayer.RUNTIME, ControlLayer.IDENTITY, ControlLayer.INFRASTRUCTURE
            }
        )


class ControlCoverageMatrix:
    VERSION = "secure-coding-lab-2026.3"

    def __init__(self) -> None:
        pre_input = PolicyAttachmentPoint.PRE_INPUT
        pre_tool = PolicyAttachmentPoint.PRE_TOOL
        pre_output = PolicyAttachmentPoint.PRE_OUTPUT
        entries = (
            OwaspRiskCoverage(OwaspAgenticRisk.T1, "Memory Poisoning", ControlLayer.DATA, False, (
                CapabilityRequirement("memory_write_integrity", ControlLayer.DATA),
                CapabilityRequirement("memory_provenance", ControlLayer.DATA),
            ), frozenset({ControlLayer.RUNTIME})),
            OwaspRiskCoverage(OwaspAgenticRisk.T2, "Tool Misuse", ControlLayer.RUNTIME, True, (
                CapabilityRequirement("tool_allowlist", ControlLayer.RUNTIME, pre_tool),
                CapabilityRequirement("inventory_scope_authorization", ControlLayer.RUNTIME, pre_tool),
                CapabilityRequirement("risk_based_ring_routing", ControlLayer.RUNTIME, pre_tool),
            )),
            OwaspRiskCoverage(OwaspAgenticRisk.T3, "Privilege Compromise", ControlLayer.RUNTIME, True, (
                CapabilityRequirement("least_privilege_tool_scopes", ControlLayer.RUNTIME, pre_tool),
                CapabilityRequirement("agent_policy_identity_binding", ControlLayer.IDENTITY, pre_tool),
                CapabilityRequirement("verified_workload_identity", ControlLayer.IDENTITY),
            ), frozenset({ControlLayer.IDENTITY})),
            OwaspRiskCoverage(OwaspAgenticRisk.T4, "Resource Overload", ControlLayer.INFRASTRUCTURE, True, (
                CapabilityRequirement("worker_timeout", ControlLayer.RUNTIME, pre_tool),
                CapabilityRequirement("payload_output_bounds", ControlLayer.RUNTIME, pre_tool),
                CapabilityRequirement("worker_concurrency_limit", ControlLayer.INFRASTRUCTURE, pre_tool),
                CapabilityRequirement("policy_latency_budget", ControlLayer.RUNTIME, pre_tool),
                CapabilityRequirement("component_readiness", ControlLayer.INFRASTRUCTURE),
                CapabilityRequirement("agent_request_budget", ControlLayer.RUNTIME, pre_input),
                CapabilityRequirement("kill_switch", ControlLayer.INFRASTRUCTURE),
            ), frozenset({ControlLayer.RUNTIME})),
            OwaspRiskCoverage(OwaspAgenticRisk.T5, "Cascading Hallucination Attacks", ControlLayer.HUMAN_PROCESS, False, (
                CapabilityRequirement("multi_agent_human_review", ControlLayer.HUMAN_PROCESS),
                CapabilityRequirement("independent_output_verification", ControlLayer.HUMAN_PROCESS),
            ), frozenset({ControlLayer.RUNTIME})),
            OwaspRiskCoverage(OwaspAgenticRisk.T6, "Intent Breaking and Goal Manipulation", ControlLayer.RUNTIME, True, (
                CapabilityRequirement("preinput_goal_policy", ControlLayer.RUNTIME, pre_input),
                CapabilityRequirement("adversarial_semantic_detection", ControlLayer.RUNTIME, pre_input),
            )),
            OwaspRiskCoverage(OwaspAgenticRisk.T7, "Misaligned and Deceptive Behaviors", ControlLayer.FRAMEWORK, False, (
                CapabilityRequirement("model_alignment_evaluation", ControlLayer.FRAMEWORK),
                CapabilityRequirement("independent_red_team", ControlLayer.HUMAN_PROCESS),
            ), frozenset({ControlLayer.HUMAN_PROCESS})),
            OwaspRiskCoverage(OwaspAgenticRisk.T8, "Repudiation and Untraceability", ControlLayer.RUNTIME, True, (
                CapabilityRequirement("correlation_id_propagation", ControlLayer.RUNTIME, pre_input),
                CapabilityRequirement("structured_policy_audit", ControlLayer.RUNTIME, pre_input),
                CapabilityRequirement("local_audit_integrity_chain", ControlLayer.RUNTIME, pre_input),
                CapabilityRequirement("persistent_audit_log", ControlLayer.INFRASTRUCTURE),
                CapabilityRequirement("tamper_evident_evidence", ControlLayer.INFRASTRUCTURE),
            )),
            OwaspRiskCoverage(OwaspAgenticRisk.T9, "Identity Spoofing and Impersonation", ControlLayer.IDENTITY, True, (
                CapabilityRequirement("agent_policy_identity_binding", ControlLayer.IDENTITY, pre_input),
                CapabilityRequirement("verified_workload_identity", ControlLayer.IDENTITY),
                CapabilityRequirement("tool_inventory_identity_check", ControlLayer.IDENTITY, pre_tool),
            ), frozenset({ControlLayer.RUNTIME})),
            OwaspRiskCoverage(OwaspAgenticRisk.T10, "Overwhelming Human-in-the-Loop", ControlLayer.HUMAN_PROCESS, False, (
                CapabilityRequirement("approval_risk_tiers", ControlLayer.HUMAN_PROCESS),
                CapabilityRequirement("approval_queue_throttling", ControlLayer.HUMAN_PROCESS),
            )),
        )
        self._entries: Mapping[OwaspAgenticRisk, OwaspRiskCoverage] = MappingProxyType(
            {entry.risk: entry for entry in entries}
        )

    def coverage_for(self, risk: OwaspAgenticRisk) -> OwaspRiskCoverage:
        return self._entries[risk]

    @property
    def entries(self) -> tuple[OwaspRiskCoverage, ...]:
        return tuple(self._entries[risk] for risk in OwaspAgenticRisk)


class ControlPlacementValidator:
    @staticmethod
    def validate_policy_annotations(
        rule_set: PolicyRuleSet,
        matrix: ControlCoverageMatrix,
    ) -> tuple[str, ...]:
        errors: list[str] = []
        for annotation in rule_set.annotations:
            try:
                risk = OwaspAgenticRisk(annotation.risk_id)
            except ValueError:
                errors.append(f"Unknown risk {annotation.risk_id}")
                continue
            coverage = matrix.coverage_for(risk)
            if not coverage.runtime_addressable:
                errors.append(f"{rule_set.name} cannot claim non-runtime risk {risk.value}")
                continue
            matches = [r for r in coverage.requirements if r.capability == annotation.capability]
            if not matches:
                errors.append(f"{annotation.capability} is not a requirement for {risk.value}")
            elif matches[0].attachment_point not in {None, rule_set.attachment_point}:
                errors.append(
                    f"{annotation.capability} belongs at {matches[0].attachment_point.value}"
                )
        return tuple(errors)


class OwaspGapAnalyzer:
    def __init__(self, matrix: ControlCoverageMatrix) -> None:
        self._matrix = matrix

    def analyze(
        self,
        evidence: Iterable[ControlEvidence],
        active_attachments: frozenset[PolicyAttachmentPoint],
        configuration_snapshot: object,
    ) -> GapAnalysisReport:
        evidence_by_capability: dict[str, list[ControlEvidence]] = {}
        for item in evidence:
            evidence_by_capability.setdefault(item.capability, []).append(item)

        findings: list[RiskFinding] = []
        flags: list[str] = []
        for coverage in self._matrix.entries:
            verified: list[str] = []
            missing: list[str] = []
            for requirement in coverage.requirements:
                candidates = evidence_by_capability.get(requirement.capability, [])
                satisfied = any(
                    item.verified
                    and item.layer is requirement.layer
                    and (
                        requirement.attachment_point is None
                        or (
                            item.attachment_point is requirement.attachment_point
                            and requirement.attachment_point in active_attachments
                        )
                    )
                    for item in candidates
                )
                (verified if satisfied else missing).append(requirement.capability)

            if not coverage.runtime_addressable:
                status = CoverageStatus.EXTERNAL_REQUIRED
                explanation = f"Primary remediation belongs to {coverage.primary_layer.value}; runtime policy cannot close this risk."
            elif not missing:
                status = CoverageStatus.VERIFIED
                explanation = "Every declared lab requirement has implemented and tested evidence."
            elif verified:
                status = CoverageStatus.PARTIAL
                explanation = "Some controls are verified, but missing capabilities prevent a full lab claim."
                flags.append(f"{coverage.risk.value} is only partial; missing: {', '.join(missing)}")
            else:
                status = CoverageStatus.MISSING
                explanation = "No required capability has verified evidence."
                flags.append(f"{coverage.risk.value} has no verified control evidence")

            findings.append(RiskFinding(
                coverage.risk, coverage.risk_name, status, coverage.primary_layer,
                tuple(verified), tuple(missing), explanation,
            ))

        fingerprint = sha256(
            json.dumps(configuration_snapshot, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()
        return GapAnalysisReport(
            self._matrix.VERSION, fingerprint, tuple(findings), tuple(flags)
        )
