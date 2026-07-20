"""Declared Chapter 1-4 evidence used by the Chapter 5 audit."""

from .coverage import ControlEvidence, ControlLayer
from .pipeline import PolicyAttachmentPoint


def secure_coding_control_evidence() -> tuple[ControlEvidence, ...]:
    pre_input = PolicyAttachmentPoint.PRE_INPUT
    pre_tool = PolicyAttachmentPoint.PRE_TOOL
    return (
        ControlEvidence("C-T2-ALLOWLIST", "tool_allowlist", ControlLayer.RUNTIME, True, True,
            "governance/coding_policy_set.py", "test_policy_engine.py::test_unlisted_tool_is_default_denied", pre_tool),
        ControlEvidence("C-T2-SCOPE", "inventory_scope_authorization", ControlLayer.RUNTIME, True, True,
            "governance/policies.py", "test_policy_engine.py::test_allow_rule_does_not_bypass_identity_inventory", pre_tool),
        ControlEvidence("C-T2-RINGS", "risk_based_ring_routing", ControlLayer.RUNTIME, True, True,
            "governance/ring_runtime.py", "test_ring_runtime.py::test_ring_one_and_two_use_restricted_worker_with_scrubbed_environment", pre_tool),
        ControlEvidence("C-T3-SCOPES", "least_privilege_tool_scopes", ControlLayer.RUNTIME, True, True,
            "governance/policies.py", "test_governance_pipeline.py::test_missing_claim_is_denied", pre_tool),
        ControlEvidence("C-T3-BIND-TOOL", "agent_policy_identity_binding", ControlLayer.IDENTITY, True, True,
            "governance/runner.py", "test_governance_pipeline.py::test_mismatched_agent_identity_is_denied_before_model_call", pre_tool),
        ControlEvidence("C-T9-BIND-INPUT", "agent_policy_identity_binding", ControlLayer.IDENTITY, True, True,
            "governance/runner.py", "test_governance_pipeline.py::test_mismatched_agent_identity_is_denied_before_model_call", pre_input),
        ControlEvidence("C-T9-TOOL-ID", "tool_inventory_identity_check", ControlLayer.IDENTITY, True, True,
            "governance/policies.py", "test_governance_pipeline.py::test_unregistered_tool_is_denied", pre_tool),
        ControlEvidence("C-T4-TIMEOUT", "worker_timeout", ControlLayer.RUNTIME, True, True,
            "governance/sandbox.py", "test_ring_runtime.py::test_worker_timeout_terminates_and_denies", pre_tool),
        ControlEvidence("C-T4-BOUNDS", "payload_output_bounds", ControlLayer.RUNTIME, True, True,
            "governance/sandbox.py", "test_ring_runtime.py::test_oversized_worker_output_is_rejected", pre_tool),
        ControlEvidence("C-T4-CONCURRENCY", "worker_concurrency_limit", ControlLayer.INFRASTRUCTURE, True, True,
            "governance/sandbox.py", "test_ring_runtime.py::test_worker_concurrency_is_bounded", pre_tool),
        ControlEvidence("C-T6-INPUT", "preinput_goal_policy", ControlLayer.RUNTIME, True, True,
            "governance/coding_policy_set.py", "test_policy_engine.py::test_priority_places_specific_deny_before_catch_all_allow", pre_input),
        ControlEvidence("C-T8-CORRELATION", "correlation_id_propagation", ControlLayer.RUNTIME, True, True,
            "governance/models.py", "test_governance_pipeline.py::test_correlation_id_is_preserved_in_decisions", pre_input),
        ControlEvidence("C-T8-STRUCTURED", "structured_policy_audit", ControlLayer.RUNTIME, True, True,
            "governance/audit.py", "test_audit.py::test_malicious_input_is_denied_audited_and_never_reaches_agent", pre_input),
        ControlEvidence("C-T8-LOCAL-CHAIN", "local_audit_integrity_chain", ControlLayer.RUNTIME, True, True,
            "governance/audit.py", "test_audit.py::test_hash_chain_detects_modified_evidence", pre_input),
    )
