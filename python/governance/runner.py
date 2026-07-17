"""Noninvasive governance wrapper around the Chapter 1B agent."""

from dataclasses import dataclass, field
from typing import Protocol

from .models import ExecutionContext
from .pipeline import (
    Decision,
    EvaluationPipeline,
    EvaluationResult,
    PolicyAttachmentPoint,
    TrustBoundary,
)


class RunnableAgent(Protocol):
    async def run(self, user_query: str) -> str: ...


@dataclass(frozen=True)
class AgentPolicySet:
    agent_id: str
    attachments: frozenset[PolicyAttachmentPoint] = field(
        default_factory=frozenset
    )


@dataclass(frozen=True)
class GovernedRunResult:
    decision: Decision
    correlation_id: str
    reason: str
    boundary: TrustBoundary | None
    output: str | None = None


class GovernedAgentRunner:
    """Own enforcement while leaving SecureCodingAgent unchanged."""

    def __init__(
        self,
        agent: RunnableAgent,
        pipeline: EvaluationPipeline,
        policy_set: AgentPolicySet,
    ) -> None:
        self._agent = agent
        self._pipeline = pipeline
        self._policy_set = policy_set

    def _identity_denial(
        self, context: ExecutionContext
    ) -> GovernedRunResult | None:
        if context.agent.agent_id == self._policy_set.agent_id:
            return None
        return GovernedRunResult(
            decision=Decision.DENY,
            correlation_id=context.correlation_id,
            reason="Execution-context agent identity does not match policy set",
            boundary=TrustBoundary.INPUT_VALIDATION,
        )

    async def _check(
        self,
        point: PolicyAttachmentPoint,
        context: ExecutionContext,
        payload: str,
    ) -> EvaluationResult | None:
        if point not in self._policy_set.attachments:
            return None
        return await self._pipeline.evaluate(point, context, payload)

    async def authorize_tool(
        self,
        tool_name: str,
        required_scope: str,
        context: ExecutionContext,
    ) -> EvaluationResult:
        """Called immediately before an actual tool invocation in Chapter 3."""

        if context.agent.agent_id != self._policy_set.agent_id:
            return EvaluationResult(
                decision=Decision.DENY,
                reason="Execution-context agent identity does not match policy set",
                boundary=TrustBoundary.TOOL_INVOCATION,
                attachment_point=PolicyAttachmentPoint.PRE_TOOL,
                correlation_id=context.correlation_id,
                policy_name="agent-identity-binding",
            )

        result = await self._check(
            PolicyAttachmentPoint.PRE_TOOL,
            context,
            f"{tool_name}|{required_scope}",
        )
        if result is None:
            return EvaluationResult(
                decision=Decision.DENY,
                reason="No PRE_TOOL policy is attached; failed closed",
                boundary=TrustBoundary.TOOL_INVOCATION,
                attachment_point=PolicyAttachmentPoint.PRE_TOOL,
                correlation_id=context.correlation_id,
                policy_name="default-deny",
            )
        return result

    async def run(
        self, query: str, context: ExecutionContext
    ) -> GovernedRunResult:
        identity_denial = self._identity_denial(context)
        if identity_denial is not None:
            return identity_denial

        input_result = await self._check(
            PolicyAttachmentPoint.PRE_INPUT, context, query
        )
        if input_result is not None and not input_result.permitted:
            return GovernedRunResult(
                decision=Decision.DENY,
                correlation_id=context.correlation_id,
                reason=input_result.reason,
                boundary=input_result.boundary,
            )

        output = await self._agent.run(query)

        output_result = await self._check(
            PolicyAttachmentPoint.PRE_OUTPUT, context, output
        )
        if output_result is not None and not output_result.permitted:
            return GovernedRunResult(
                decision=Decision.DENY,
                correlation_id=context.correlation_id,
                reason=output_result.reason,
                boundary=output_result.boundary,
            )

        return GovernedRunResult(
            decision=Decision.PERMIT,
            correlation_id=context.correlation_id,
            reason="Request passed every active governance boundary",
            boundary=None,
            output=output,
        )
