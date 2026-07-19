"""Domain policies for the enterprise SecureCodingAgent."""

import re

from .pipeline import PolicyAttachmentPoint
from .policy_engine import (
    ConditionKind,
    PolicyAction,
    PolicyCondition,
    PolicyRegistry,
    PolicyRule,
    PolicyRuleSet,
    PolicyTraceAnnotation,
    PolicyVersion,
)
from .policies import SECRET_PATTERN


class SecureCodingPolicySet:
    VERSION_1_0_0 = PolicyVersion(1, 0, 0)
    VERSION_1_1_0 = PolicyVersion(1, 1, 0)
    SUPPORTED_VERSIONS = frozenset({VERSION_1_0_0, VERSION_1_1_0})

    @classmethod
    def register_all(cls, registry: PolicyRegistry) -> None:
        for version in sorted(cls.SUPPORTED_VERSIONS):
            registry.register(cls.input_rules(version))
            registry.register(cls.tool_rules(version))
            registry.register(cls.output_rules(version))

    @classmethod
    def _require_supported(cls, version: PolicyVersion) -> None:
        if version not in cls.SUPPORTED_VERSIONS:
            raise ValueError(f"Unsupported policy version {version}")

    @classmethod
    def input_rules(cls, version: PolicyVersion) -> PolicyRuleSet:
        cls._require_supported(version)
        rules = [
            PolicyRule(
                "deny_ignore_previous_instructions",
                100,
                PolicyCondition(
                    ConditionKind.INPUT_CONTAINS,
                    "ignore previous instructions",
                ),
                PolicyAction.DENY,
                "Block a common direct goal-manipulation pattern",
            ),
            PolicyRule(
                "deny_read_all_env_files",
                110,
                PolicyCondition(
                    ConditionKind.INPUT_CONTAINS,
                    "read every .env",
                ),
                PolicyAction.DENY,
                "Block broad credential-file collection",
            ),
            PolicyRule(
                "deny_print_environment",
                120,
                PolicyCondition(
                    ConditionKind.INPUT_CONTAINS,
                    "print environment variables",
                ),
                PolicyAction.DENY,
                "Block environment-variable exfiltration requests",
            ),
            PolicyRule(
                "deny_reveal_api_keys",
                130,
                PolicyCondition(
                    ConditionKind.INPUT_CONTAINS,
                    "reveal api keys",
                ),
                PolicyAction.DENY,
                "Block direct secret-exfiltration requests",
            ),
        ]
        if version >= cls.VERSION_1_1_0:
            rules.append(
                PolicyRule(
                    "deny_npmrc_collection",
                    140,
                    PolicyCondition(
                        ConditionKind.INPUT_CONTAINS,
                        "read every .npmrc",
                    ),
                    PolicyAction.DENY,
                    "Version 1.1 adds protection for package-registry credentials",
                )
            )
        rules.append(
            PolicyRule(
                "allow_standard_code_review",
                9999,
                PolicyCondition(ConditionKind.MATCH_ALL),
                PolicyAction.ALLOW,
                "Allow ordinary secure-code review requests",
            )
        )
        return PolicyRuleSet(
            "secure-coding-input",
            version,
            PolicyAttachmentPoint.PRE_INPUT,
            tuple(rules),
            annotations=(
                PolicyTraceAnnotation(
                    "T6",
                    "preinput_goal_policy",
                    "Versioned PRE_INPUT rules reject known goal-manipulation requests",
                ),
            ),
        )

    @classmethod
    def tool_rules(cls, version: PolicyVersion) -> PolicyRuleSet:
        cls._require_supported(version)
        return PolicyRuleSet(
            "secure-coding-tool",
            version,
            PolicyAttachmentPoint.PRE_TOOL,
            (
                PolicyRule(
                    "deny_production_deployer",
                    100,
                    PolicyCondition(
                        ConditionKind.TOOL_IS, "production-deployer"
                    ),
                    PolicyAction.DENY,
                    "Production deployment is prohibited in this lab",
                ),
                PolicyRule(
                    "deny_terminal_executor",
                    110,
                    PolicyCondition(
                        ConditionKind.TOOL_IS, "terminal-executor"
                    ),
                    PolicyAction.DENY,
                    "Arbitrary terminal execution is prohibited",
                ),
                PolicyRule(
                    "deny_git_push",
                    120,
                    PolicyCondition(ConditionKind.TOOL_IS, "git-push"),
                    PolicyAction.DENY,
                    "Direct pushes require a later approval workflow",
                ),
                PolicyRule(
                    "allow_prompt_code_reader",
                    490,
                    PolicyCondition(
                        ConditionKind.TOOL_IS, "prompt-code-reader"
                    ),
                    PolicyAction.ALLOW,
                    "Permit the in-memory reader for code already in the prompt",
                ),
                PolicyRule(
                    "allow_repository_reader",
                    500,
                    PolicyCondition(
                        ConditionKind.TOOL_IS, "repository-reader"
                    ),
                    PolicyAction.ALLOW,
                    "Permit the governed read-only repository tool",
                ),
                PolicyRule(
                    "allow_unit_test_runner",
                    510,
                    PolicyCondition(
                        ConditionKind.TOOL_IS, "unit-test-runner"
                    ),
                    PolicyAction.ALLOW,
                    "Permit the future sandboxed unit-test runner",
                ),
                PolicyRule(
                    "allow_sast_scanner",
                    520,
                    PolicyCondition(ConditionKind.TOOL_IS, "sast-scanner"),
                    PolicyAction.ALLOW,
                    "Permit the future read-only SAST scanner",
                ),
                PolicyRule(
                    "deny_unlisted_tool",
                    9999,
                    PolicyCondition(ConditionKind.MATCH_ALL),
                    PolicyAction.DENY,
                    "Explicit allowlist with default deny",
                ),
            ),
            annotations=(
                PolicyTraceAnnotation(
                    "T2",
                    "tool_allowlist",
                    "PRE_TOOL policy explicitly allows known tools and denies unknown tools",
                ),
                PolicyTraceAnnotation(
                    "T3",
                    "least_privilege_tool_scopes",
                    "Tool policy is layered with immutable inventory and scope authorization",
                ),
            ),
        )

    @classmethod
    def output_rules(cls, version: PolicyVersion) -> PolicyRuleSet:
        cls._require_supported(version)
        patterns = [
            PolicyRule(
                "deny_high_confidence_credential",
                100,
                PolicyCondition(ConditionKind.OUTPUT_REGEX, SECRET_PATTERN),
                PolicyAction.DENY,
                "Block high-confidence credential shapes",
            )
        ]
        if version >= cls.VERSION_1_1_0:
            patterns.append(
                PolicyRule(
                    "deny_private_key_material",
                    110,
                    PolicyCondition(
                        ConditionKind.OUTPUT_REGEX,
                        re.compile(
                            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
                            re.IGNORECASE,
                        ),
                    ),
                    PolicyAction.DENY,
                    "Version 1.1 blocks private-key material",
                )
            )
        patterns.append(
            PolicyRule(
                "allow_standard_security_review",
                9999,
                PolicyCondition(ConditionKind.MATCH_ALL),
                PolicyAction.ALLOW,
                "Allow ordinary security language without false positives",
            )
        )
        return PolicyRuleSet(
            "secure-coding-output",
            version,
            PolicyAttachmentPoint.PRE_OUTPUT,
            tuple(patterns),
            annotations=(),
        )
