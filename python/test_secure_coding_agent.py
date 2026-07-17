from secure_coding_agent import AgentConfiguration, BASELINE_INSTRUCTIONS


def test_configuration_is_read_only_metadata() -> None:
    config = AgentConfiguration()
    assert config.agent_name == "SecureCodingAgent"


def test_baseline_discloses_no_tool_capability() -> None:
    normalized = BASELINE_INSTRUCTIONS.lower()
    assert "no filesystem" in normalized
    assert "never claim" in normalized
    assert "untrusted data" in normalized
