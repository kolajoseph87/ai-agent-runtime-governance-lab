"""Versioned, immutable policy primitives and evaluators for Chapter 3."""

from dataclasses import dataclass, field
from enum import Enum
from re import Pattern

from .models import ExecutionContext
from .pipeline import PolicyAttachmentPoint


class PolicyAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ConditionKind(str, Enum):
    MATCH_ALL = "match_all"
    INPUT_CONTAINS = "input_contains"
    TOOL_IS = "tool_is"
    OUTPUT_REGEX = "output_regex"


@dataclass(frozen=True, order=True)
class PolicyVersion:
    major: int
    minor: int
    patch: int

    def __post_init__(self) -> None:
        if min(self.major, self.minor, self.patch) < 0:
            raise ValueError("Policy version components cannot be negative")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class PolicyCondition:
    kind: ConditionKind
    value: str | Pattern[str] | None = None


@dataclass(frozen=True)
class PolicyRule:
    name: str
    priority: int
    condition: PolicyCondition
    action: PolicyAction
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Policy rule name is required")
        if self.priority < 0:
            raise ValueError("Policy priority cannot be negative")


@dataclass(frozen=True)
class PolicyTraceAnnotation:
    risk_id: str
    capability: str
    justification: str


@dataclass(frozen=True)
class PolicyRuleSet:
    name: str
    version: PolicyVersion
    attachment_point: PolicyAttachmentPoint
    rules: tuple[PolicyRule, ...] = field(default_factory=tuple)
    annotations: tuple[PolicyTraceAnnotation, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class PolicyEvaluationContext:
    execution_context: ExecutionContext
    attachment_point: PolicyAttachmentPoint
    input_text: str = ""
    tool_name: str = ""
    required_scope: str = ""
    output_text: str = ""


@dataclass(frozen=True)
class RuleEvaluationResult:
    permitted: bool
    reason: str
    rule_name: str
    rule_set_name: str
    policy_version: str


class PolicyValidationError(ValueError):
    """Raised before a malformed rule set can reach a runtime runner."""


class PolicyValidator:
    @staticmethod
    def validate(rule_set: PolicyRuleSet) -> tuple[str, ...]:
        errors: list[str] = []
        if not rule_set.name.strip():
            errors.append("Rule-set name is required")
        if not rule_set.rules:
            errors.append("Rule set must contain at least one rule")

        names = [rule.name for rule in rule_set.rules]
        duplicate_names = sorted(
            name for name in set(names) if names.count(name) > 1
        )
        if duplicate_names:
            errors.append(
                "Duplicate rule names: " + ", ".join(duplicate_names)
            )

        priorities = [rule.priority for rule in rule_set.rules]
        duplicate_priorities = sorted(
            value for value in set(priorities) if priorities.count(value) > 1
        )
        if duplicate_priorities:
            errors.append(
                "Ambiguous duplicate priorities: "
                + ", ".join(str(value) for value in duplicate_priorities)
            )

        catch_all = [
            rule
            for rule in rule_set.rules
            if rule.condition.kind is ConditionKind.MATCH_ALL
        ]
        if len(catch_all) != 1:
            errors.append("Exactly one catch-all rule is required")
        elif catch_all[0].priority != max(priorities):
            errors.append("Catch-all rule must have the lowest precedence")

        for rule in rule_set.rules:
            if (
                rule.condition.kind is not ConditionKind.MATCH_ALL
                and rule.condition.value is None
            ):
                errors.append(f"Rule {rule.name} requires a condition value")

        for annotation in rule_set.annotations:
            if not annotation.risk_id or not annotation.capability:
                errors.append("Policy annotations require a risk ID and capability")

        return tuple(errors)

    @classmethod
    def require_valid(cls, rule_set: PolicyRuleSet) -> None:
        errors = cls.validate(rule_set)
        if errors:
            raise PolicyValidationError("; ".join(errors))


class PolicyRegistry:
    """Store immutable rule sets by name and semantic version."""

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], PolicyRuleSet] = {}

    def register(self, rule_set: PolicyRuleSet) -> None:
        PolicyValidator.require_valid(rule_set)
        key = (rule_set.name, str(rule_set.version))
        if key in self._store:
            raise PolicyValidationError(
                f"Rule set {rule_set.name}@{rule_set.version} is already registered"
            )
        self._store[key] = rule_set

    def load(self, name: str, version: str) -> PolicyRuleSet:
        try:
            return self._store[(name, version)]
        except KeyError as exc:
            raise KeyError(f"Rule set {name}@{version} not found") from exc


class PolicyEvaluator:
    """Pre-sort once, evaluate first match, and default deny."""

    def __init__(self, rule_set: PolicyRuleSet) -> None:
        PolicyValidator.require_valid(rule_set)
        self._rule_set = rule_set
        self._sorted_rules = tuple(
            sorted(rule_set.rules, key=lambda rule: rule.priority)
        )

    def evaluate(
        self, context: PolicyEvaluationContext
    ) -> RuleEvaluationResult:
        try:
            if context.attachment_point is not self._rule_set.attachment_point:
                return self._deny(
                    "Attachment point does not match the rule set",
                    "attachment-point-binding",
                )
            for rule in self._sorted_rules:
                if self._matches(rule.condition, context):
                    return RuleEvaluationResult(
                        permitted=rule.action is PolicyAction.ALLOW,
                        reason=f"Rule '{rule.name}' matched",
                        rule_name=rule.name,
                        rule_set_name=self._rule_set.name,
                        policy_version=str(self._rule_set.version),
                    )
            return self._deny("No rule matched; default deny", "default-deny")
        except Exception as exc:
            return self._deny(
                f"Policy evaluator failed closed: {type(exc).__name__}",
                "evaluator-exception",
            )

    def _deny(self, reason: str, rule_name: str) -> RuleEvaluationResult:
        return RuleEvaluationResult(
            permitted=False,
            reason=reason,
            rule_name=rule_name,
            rule_set_name=self._rule_set.name,
            policy_version=str(self._rule_set.version),
        )

    @staticmethod
    def _matches(
        condition: PolicyCondition, context: PolicyEvaluationContext
    ) -> bool:
        if condition.kind is ConditionKind.MATCH_ALL:
            return True
        if condition.kind is ConditionKind.INPUT_CONTAINS:
            return str(condition.value).lower() in context.input_text.lower()
        if condition.kind is ConditionKind.TOOL_IS:
            return str(condition.value).casefold() == context.tool_name.casefold()
        if condition.kind is ConditionKind.OUTPUT_REGEX:
            pattern = condition.value
            if not hasattr(pattern, "search"):
                raise TypeError("OUTPUT_REGEX requires a compiled pattern")
            return bool(pattern.search(context.output_text))  # type: ignore[union-attr]
        raise ValueError(f"Unsupported condition kind: {condition.kind}")

    async def evaluate_input(
        self, context: ExecutionContext, payload: str
    ) -> tuple[bool, str]:
        result = self.evaluate(
            PolicyEvaluationContext(
                execution_context=context,
                attachment_point=PolicyAttachmentPoint.PRE_INPUT,
                input_text=payload,
            )
        )
        return result.permitted, self._pipeline_reason(result)

    async def evaluate_tool(
        self, context: ExecutionContext, payload: str
    ) -> tuple[bool, str]:
        try:
            tool_name, required_scope = payload.split("|", maxsplit=1)
        except ValueError:
            return False, "Malformed tool authorization request"
        result = self.evaluate(
            PolicyEvaluationContext(
                execution_context=context,
                attachment_point=PolicyAttachmentPoint.PRE_TOOL,
                tool_name=tool_name,
                required_scope=required_scope,
            )
        )
        return result.permitted, self._pipeline_reason(result)

    async def evaluate_output(
        self, context: ExecutionContext, payload: str
    ) -> tuple[bool, str]:
        result = self.evaluate(
            PolicyEvaluationContext(
                execution_context=context,
                attachment_point=PolicyAttachmentPoint.PRE_OUTPUT,
                output_text=payload,
            )
        )
        return result.permitted, self._pipeline_reason(result)

    @staticmethod
    def _pipeline_reason(result: RuleEvaluationResult) -> str:
        return (
            f"{result.reason} "
            f"[{result.rule_set_name}@{result.policy_version}]"
        )
