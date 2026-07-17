"""Immutable identity and request-context models."""

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone


@dataclass(frozen=True)
class AgentPrincipal:
    """The human or calling service on whose behalf the agent operates."""

    principal_id: str
    tenant_id: str
    claims: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class AgentIdentity:
    """The independently identifiable agent performing the work."""

    agent_id: str
    version: str
    role: str


@dataclass(frozen=True)
class ToolIdentity:
    """A versioned external capability and its maximum approved scopes."""

    tool_name: str
    tool_version: str
    allowed_scopes: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class ExecutionContext:
    """An immutable security snapshot created at request entry."""

    correlation_id: str
    session_id: str
    principal: AgentPrincipal
    agent: AgentIdentity
    tool_inventory: frozenset[ToolIdentity] = field(default_factory=frozenset)
    workspace: str = "synthetic://prompt-only"
    environment: str = "development"
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def with_new_claims(self, claims: frozenset[str]) -> "ExecutionContext":
        """Create a new snapshot; never change the current request in place."""

        return replace(
            self,
            principal=replace(self.principal, claims=claims),
        )
