"""Fail-closed policy pipeline with explicit interception points."""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Protocol

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


class EvaluationOutcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ERROR = "ERROR"


@dataclass(frozen=True)
class PolicyEvaluationEvent:
    outcome: EvaluationOutcome
    reason: str
    boundary: TrustBoundary
    attachment_point: PolicyAttachmentPoint
    correlation_id: str
    trace_id: str | None
    principal_id: str
    agent_id: str
    policy_name: str
    duration_ms: float


class EvaluationObserver(Protocol):
    def __call__(self, event: PolicyEvaluationEvent) -> None: ...


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
        self._observers: list[EvaluationObserver] = []

    def attach(
        self,
        point: PolicyAttachmentPoint,
        policy_name: str,
        evaluator: Evaluator,
    ) -> None:
        self._evaluators[point].append((policy_name, evaluator))

    def attach_observer(self, observer: EvaluationObserver) -> None:
        self._observers.append(observer)

    def _notify(
        self,
        *,
        outcome: EvaluationOutcome,
        reason: str,
        point: PolicyAttachmentPoint,
        context: ExecutionContext,
        policy_name: str,
        started_at: float,
    ) -> bool:
        """Return False if evidence emission fails so execution can fail closed."""

        event = PolicyEvaluationEvent(
            outcome=outcome,
            reason=reason,
            boundary=BOUNDARY_BY_POINT[point],
            attachment_point=point,
            correlation_id=context.correlation_id,
            trace_id=context.trace_id,
            principal_id=context.principal.principal_id,
            agent_id=context.agent.agent_id,
            policy_name=policy_name,
            duration_ms=round((time.perf_counter() - started_at) * 1000, 3),
        )
        try:
            for observer in tuple(self._observers):
                observer(event)
        except Exception:
            return False
        return True

    @property
    def attachment_points(self) -> frozenset[PolicyAttachmentPoint]:
        return frozenset(
            point for point, evaluators in self._evaluators.items() if evaluators
        )

    def configuration_snapshot(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        """Return immutable, non-callable metadata for CI/audit fingerprinting."""
        return tuple(
            sorted(
                (
                    point.value,
                    tuple(name for name, _ in evaluators),
                )
                for point, evaluators in self._evaluators.items()
                if evaluators
            )
        )

    async def evaluate(
        self,
        point: PolicyAttachmentPoint,
        context: ExecutionContext,
        payload: str,
    ) -> EvaluationResult:
        boundary = BOUNDARY_BY_POINT[point]
        evaluators = self._evaluators.get(point, [])

        if not evaluators:
            result = EvaluationResult(
                decision=Decision.DENY,
                reason="No evaluator is attached at the required boundary",
                boundary=boundary,
                attachment_point=point,
                correlation_id=context.correlation_id,
                policy_name="default-deny",
            )
            self._notify(
                outcome=EvaluationOutcome.DENY,
                reason=result.reason,
                point=point,
                context=context,
                policy_name=result.policy_name,
                started_at=time.perf_counter(),
            )
            return result

        for policy_name, evaluator in evaluators:
            started_at = time.perf_counter()
            try:
                permitted, reason = await asyncio.wait_for(
                    evaluator(context, payload),
                    timeout=self._timeout_seconds,
                )
            except Exception as exc:
                reason = f"Policy evaluation failed closed: {type(exc).__name__}"
                self._notify(
                    outcome=EvaluationOutcome.ERROR,
                    reason=reason,
                    point=point,
                    context=context,
                    policy_name=policy_name,
                    started_at=started_at,
                )
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason=reason,
                    boundary=boundary,
                    attachment_point=point,
                    correlation_id=context.correlation_id,
                    policy_name=policy_name,
                )

            if not permitted:
                if not self._notify(
                    outcome=EvaluationOutcome.DENY,
                    reason=reason,
                    point=point,
                    context=context,
                    policy_name=policy_name,
                    started_at=started_at,
                ):
                    reason = "Audit evidence emission failed closed"
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason=reason,
                    boundary=boundary,
                    attachment_point=point,
                    correlation_id=context.correlation_id,
                    policy_name=policy_name,
                )

            if not self._notify(
                outcome=EvaluationOutcome.ALLOW,
                reason=reason,
                point=point,
                context=context,
                policy_name=policy_name,
                started_at=started_at,
            ):
                return EvaluationResult(
                    decision=Decision.DENY,
                    reason="Audit evidence emission failed closed",
                    boundary=boundary,
                    attachment_point=point,
                    correlation_id=context.correlation_id,
                    policy_name="audit-fail-closed",
                )

        return EvaluationResult(
            decision=Decision.PERMIT,
            reason="All attached policies permitted progression",
            boundary=boundary,
            attachment_point=point,
            correlation_id=context.correlation_id,
            policy_name="pipeline",
        )
