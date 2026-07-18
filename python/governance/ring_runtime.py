"""Layer Chapter 4 execution routing after Chapter 3 authorization."""

from dataclasses import dataclass
from typing import Any, Protocol

from .hot_path import HotPathVerdict
from .rings import ExecutionRing, ToolInvocation, ToolRingClassifier
from .sandbox import RestrictedWorkerExecutor


class ToolAuthorizer(Protocol):
    async def authorize_tool(self, tool_name: str, required_scope: str, context: Any) -> Any: ...


class HotPathClient(Protocol):
    def evaluate(self, tool_name: str, ring: int, principal_id: str) -> HotPathVerdict: ...


@dataclass(frozen=True)
class ToolExecutionResult:
    status: str
    tool_name: str
    ring: str | None
    path: str | None
    correlation_id: str
    reason: str
    output: dict[str, Any] | None = None


class RingAwareToolRuntime:
    def __init__(
        self,
        authorizer: ToolAuthorizer,
        classifier: ToolRingClassifier,
        hot_path: HotPathClient | None,
        worker: RestrictedWorkerExecutor,
    ) -> None:
        self._authorizer = authorizer
        self._classifier = classifier
        self._hot_path = hot_path
        self._worker = worker

    async def invoke(self, invocation: ToolInvocation) -> ToolExecutionResult:
        correlation_id = invocation.context.correlation_id
        try:
            authorization = await self._authorizer.authorize_tool(
                invocation.tool_name, invocation.required_scope, invocation.context
            )
            if not authorization.permitted:
                return self._deny(invocation, None, "pre-tool-policy", authorization.reason)

            assignment = self._classifier.classify(invocation.tool_name)
            if assignment.ring is ExecutionRing.RING_3_PRIVILEGED:
                return self._deny(
                    invocation,
                    assignment.ring,
                    "human-approval-required",
                    "Ring 3 tools are disabled until a human approval service exists",
                )

            if assignment.ring is ExecutionRing.RING_0_IN_MEMORY:
                if self._hot_path is None:
                    return self._deny(invocation, assignment.ring, "rust-hot-path", "Rust evaluator unavailable")
                verdict = self._hot_path.evaluate(
                    invocation.tool_name, int(assignment.ring), invocation.principal_id
                )
                if verdict is not HotPathVerdict.ALLOW:
                    return self._deny(
                        invocation, assignment.ring, "rust-hot-path", f"Hot-path verdict: {verdict.name}"
                    )
                return ToolExecutionResult(
                    "ok", invocation.tool_name, assignment.ring.name, "rust-hot-path",
                    correlation_id, "Authorized in-memory operation",
                    {"mode": "in-memory", "argument_names": sorted(invocation.arguments)},
                )

            output = await self._worker.execute(
                invocation.tool_name,
                assignment.ring,
                invocation.arguments,
                correlation_id,
            )
            return ToolExecutionResult(
                "ok", invocation.tool_name, assignment.ring.name, "restricted-worker",
                correlation_id, "Worker completed exactly one mock operation", output,
            )
        except Exception as exc:
            return self._deny(
                invocation, None, "fail-closed", f"Runtime failure: {type(exc).__name__}"
            )

    @staticmethod
    def _deny(
        invocation: ToolInvocation,
        ring: ExecutionRing | None,
        path: str,
        reason: str,
    ) -> ToolExecutionResult:
        return ToolExecutionResult(
            "denied", invocation.tool_name, ring.name if ring is not None else None,
            path, invocation.context.correlation_id, reason,
        )
