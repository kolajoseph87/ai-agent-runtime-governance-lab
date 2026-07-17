"""Fail-closed policy pipeline with explicit interception points."""

import asyncio
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable

from .models import ExecutionContext


class TrustBoundary(str, Enum):
    INPUT_VALIDATION = "input_validation"
    TOOL_INVOCATION = "tool_invocation"
    OUTPUT_FILTERING = "output_filtering"


class PolicyAttachmentPoint(str, Enum):
    PRE_INPUT = "pre_input"
    PRE_TOOL = "pre_tool"
    PRE_OUTPUT = "pre_output"


BOUNDARY_BY_POINT = {
    PolicyAttachmentPoint.PRE_INPUT: TrustBoundary.INPUT_VALIDATION,
    PolicyAttachmentPoint.PRE_TOOL: TrustBoundary.TOOL_INVOCATION,
    PolicyAttachmentPoint.PRE_OUTPUT: TrustBoundary.OUTPUT_FILTERING,
}


class Decision(str, Enum):
    PERMIT = "PERMIT"
    DENY = "DENY"


@dataclass(frozen=True)
class EvaluationResult:
    decision: Decision
    reason: str
    boundary: TrustBoundary
    attachment_point: PolicyAttachmentPoint
    correlation_id: str
    policy_name: str

    @property
    def permitted(self) -> bool:
        return self.decision is Decision.PERMIT


Evaluator = Callable[
    [ExecutionContext, str], Awaitable[tuple[bool, str]]
]


class EvaluationPipeline:
    """Run evaluators sequentially and stop immediately on denial."""

    def __init__(self, timeout_seconds: float = 1.0) -> None:
        self._evaluators: dict[
            PolicyAttachmentPoint, list[tuple[str, Evaluator]]
        ] = defaultdict(list)
        self._timeout_seconds = timeout_seconds

    def attach(
        self,
        point: PolicyAttachmentPoint,
        policy_name: str,
        evaluator: Evaluator,
    ) -> None:
        self._evaluators[point].append((policy_name, evaluator))

    async def evaluate(
        self,
        point: PolicyAttachmentPoint,
        context: ExecutionContext,
        payload: str,
    ) -> EvaluationResult:
        boundary = BOUNDARY_BY_POINT[point]
        evaluators = self._evaluators.get(point, [])

        if not evaluators:
            return EvaluationResult(
                decision=Decision.DENY,
                reason="No evaluator is attached at the required boundary",
                boundary=boundary,
                attachment_point=point,
                correlation_id=context.correlation_id,
                policy_name="default-deny",
            )

        for policy_name, evaluator in evaluators:
            try:
                permitted, reason = await asyncio.wait_for(
                    evaluator(context, payload),
                    timeout=self._timeout_seconds,
                )
            except Exception as exc:
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason=f"Policy evaluation failed closed: {type(exc).__name__}",
                    boundary=boundary,
                    attachment_point=point,
                    correlation_id=context.correlation_id,
                    policy_name=policy_name,
                )

            if not permitted:
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason=reason,
                    boundary=boundary,
                    attachment_point=point,
                    correlation_id=context.correlation_id,
                    policy_name=policy_name,
                )

        return EvaluationResult(
            decision=Decision.PERMIT,
            reason="All attached policies permitted progression",
            boundary=boundary,
            attachment_point=point,
            correlation_id=context.correlation_id,
            policy_name="pipeline",
        )
