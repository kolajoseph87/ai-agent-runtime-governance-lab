"""Immutable execution-ring model for the SecureCodingAgent."""

from dataclasses import dataclass
from enum import IntEnum
from types import MappingProxyType
from typing import Any, Mapping

from .models import ExecutionContext


class ExecutionRing(IntEnum):
    RING_0_IN_MEMORY = 0
    RING_1_LOCAL_RESTRICTED = 1
    RING_2_UNTRUSTED_OR_EXTERNAL = 2
    RING_3_PRIVILEGED = 3


@dataclass(frozen=True)
class ToolRingAssignment:
    tool_name: str
    ring: ExecutionRing
    justification: str


class ToolRingClassifier:
    def __init__(self, assignments: Mapping[str, ToolRingAssignment]) -> None:
        copied = dict(assignments)
        if not copied:
            raise ValueError("At least one ring assignment is required")
        for key, assignment in copied.items():
            if key != assignment.tool_name:
                raise ValueError(f"Assignment key does not match {assignment.tool_name}")
        self._assignments = MappingProxyType(copied)

    def classify(self, tool_name: str) -> ToolRingAssignment:
        try:
            return self._assignments[tool_name]
        except KeyError as exc:
            raise KeyError(f"Tool {tool_name!r} has no execution-ring assignment") from exc


SECURE_CODING_ASSIGNMENTS = MappingProxyType(
    {
        "prompt-code-reader": ToolRingAssignment(
            "prompt-code-reader",
            ExecutionRing.RING_0_IN_MEMORY,
            "Reads only code already present in immutable request memory",
        ),
        "repository-reader": ToolRingAssignment(
            "repository-reader",
            ExecutionRing.RING_1_LOCAL_RESTRICTED,
            "Reads sensitive workspace data and therefore uses a restricted worker",
        ),
        "sast-scanner": ToolRingAssignment(
            "sast-scanner",
            ExecutionRing.RING_1_LOCAL_RESTRICTED,
            "Analyzes code locally with no network and no mutation",
        ),
        "unit-test-runner": ToolRingAssignment(
            "unit-test-runner",
            ExecutionRing.RING_2_UNTRUSTED_OR_EXTERNAL,
            "Executes potentially hostile repository code",
        ),
        "dependency-advisory-lookup": ToolRingAssignment(
            "dependency-advisory-lookup",
            ExecutionRing.RING_2_UNTRUSTED_OR_EXTERNAL,
            "Would cross a network trust boundary in production",
        ),
        "terminal-executor": ToolRingAssignment(
            "terminal-executor",
            ExecutionRing.RING_3_PRIVILEGED,
            "Arbitrary command execution has broad host impact",
        ),
        "git-push": ToolRingAssignment(
            "git-push",
            ExecutionRing.RING_3_PRIVILEGED,
            "Changes an external source-of-truth repository",
        ),
        "production-deployer": ToolRingAssignment(
            "production-deployer",
            ExecutionRing.RING_3_PRIVILEGED,
            "Changes production and requires explicit human approval",
        ),
    }
)


@dataclass(frozen=True)
class ToolInvocation:
    context: ExecutionContext
    tool_name: str
    required_scope: str
    arguments: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.tool_name or not self.required_scope:
            raise ValueError("Tool name and required scope are mandatory")
        object.__setattr__(self, "arguments", MappingProxyType(dict(self.arguments)))

    @property
    def principal_id(self) -> str:
        return self.context.principal.principal_id
