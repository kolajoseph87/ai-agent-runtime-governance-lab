"""Restricted demonstration worker: deterministic mock tools only.

This is process isolation, not an OS sandbox. It never executes user commands,
opens repository paths, or enables network access.
"""

import json
import os
import sys
from typing import Any

MAX_INPUT_BYTES = 64 * 1024
ALLOWED_KEYS = frozenset({"tool", "arguments", "correlation_id"})
MOCK_TOOLS = frozenset(
    {"repository-reader", "sast-scanner", "unit-test-runner", "dependency-advisory-lookup"}
)


def _reject(reason: str) -> int:
    print(json.dumps({"status": "denied", "reason": reason}))
    return 1


def _validate(payload: Any) -> tuple[str, dict[str, Any], str] | None:
    if not isinstance(payload, dict) or set(payload) != ALLOWED_KEYS:
        return None
    tool = payload.get("tool")
    arguments = payload.get("arguments")
    correlation_id = payload.get("correlation_id")
    if tool not in MOCK_TOOLS or not isinstance(arguments, dict):
        return None
    if not isinstance(correlation_id, str) or not correlation_id:
        return None
    return tool, arguments, correlation_id


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        return _reject("payload too large")
    try:
        validated = _validate(json.loads(raw))
    except (UnicodeDecodeError, json.JSONDecodeError):
        validated = None
    if validated is None:
        return _reject("invalid schema or unregistered worker tool")

    tool, arguments, correlation_id = validated
    # Proves the parent secret was not inherited; never prints any secret value.
    environment_scrubbed = "OPENAI_API_KEY" not in os.environ
    results: dict[str, Any] = {
        "repository-reader": {"files_examined": 0, "mode": "mock-read-only"},
        "sast-scanner": {"findings": [], "mode": "mock-no-filesystem"},
        "unit-test-runner": {"tests_run": 0, "mode": "mock-no-code-execution"},
        "dependency-advisory-lookup": {"advisories": [], "mode": "mock-no-network"},
    }
    print(
        json.dumps(
            {
                "status": "ok",
                "tool": tool,
                "correlation_id": correlation_id,
                "environment_scrubbed": environment_scrubbed,
                "result": results[tool],
                "received_argument_names": sorted(arguments),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
