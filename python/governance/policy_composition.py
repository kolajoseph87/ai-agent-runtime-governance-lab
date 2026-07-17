"""Compose versioned policy evaluators without changing agent business logic."""

from .coding_policy_set import SecureCodingPolicySet
from .pipeline import EvaluationPipeline, PolicyAttachmentPoint
from .policies import authorize_tool_request, require_code_review_claim
from .policy_engine import PolicyEvaluator, PolicyRegistry


def create_policy_registry() -> PolicyRegistry:
    registry = PolicyRegistry()
    SecureCodingPolicySet.register_all(registry)
    return registry


def create_versioned_pipeline(
    policy_version: str = "1.1.0",
    timeout_seconds: float = 1.0,
) -> EvaluationPipeline:
    registry = create_policy_registry()
    input_evaluator = PolicyEvaluator(
        registry.load("secure-coding-input", policy_version)
    )
    tool_evaluator = PolicyEvaluator(
        registry.load("secure-coding-tool", policy_version)
    )
    output_evaluator = PolicyEvaluator(
        registry.load("secure-coding-output", policy_version)
    )

    pipeline = EvaluationPipeline(timeout_seconds=timeout_seconds)
    pipeline.attach(
        PolicyAttachmentPoint.PRE_INPUT,
        "require-code-review-claim",
        require_code_review_claim,
    )
    pipeline.attach(
        PolicyAttachmentPoint.PRE_INPUT,
        f"secure-coding-input@{policy_version}",
        input_evaluator.evaluate_input,
    )
    pipeline.attach(
        PolicyAttachmentPoint.PRE_TOOL,
        f"secure-coding-tool@{policy_version}",
        tool_evaluator.evaluate_tool,
    )
    pipeline.attach(
        PolicyAttachmentPoint.PRE_TOOL,
        "authorize-tool-identity-and-scope",
        authorize_tool_request,
    )
    pipeline.attach(
        PolicyAttachmentPoint.PRE_OUTPUT,
        f"secure-coding-output@{policy_version}",
        output_evaluator.evaluate_output,
    )
    return pipeline
