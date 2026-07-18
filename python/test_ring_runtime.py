import asyncio
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from governance.hot_path import HotPathVerdict, RustHotPathClient
from governance.ring_runtime import RingAwareToolRuntime
from governance.rings import (
    SECURE_CODING_ASSIGNMENTS,
    ExecutionRing,
    ToolInvocation,
    ToolRingAssignment,
    ToolRingClassifier,
)
from governance.sandbox import RestrictedWorkerExecutor, SandboxExecutionError
from governed_agent_demo import create_context


class Decision:
    def __init__(self, permitted: bool, reason: str = "test decision") -> None:
        self.permitted = permitted
        self.reason = reason


class FakeAuthorizer:
    def __init__(self, permitted: bool = True) -> None:
        self.permitted = permitted

    async def authorize_tool(self, tool_name, required_scope, context):
        return Decision(self.permitted)


class FakeHotPath:
    def __init__(self, verdict=HotPathVerdict.ALLOW) -> None:
        self.verdict = verdict

    def evaluate(self, tool_name, ring, principal_id):
        return self.verdict


def worker() -> RestrictedWorkerExecutor:
    return RestrictedWorkerExecutor(
        Path(__file__).with_name("sandbox_worker.py"), timeout_seconds=1
    )


def invocation(tool: str, scope: str = "repo:read", arguments=None):
    return ToolInvocation(create_context(), tool, scope, arguments or {})


def test_classifier_is_immutable_and_unknown_tool_fails_closed():
    classifier = ToolRingClassifier(SECURE_CODING_ASSIGNMENTS)
    assignment = classifier.classify("unit-test-runner")
    assert assignment.ring is ExecutionRing.RING_2_UNTRUSTED_OR_EXTERNAL
    with pytest.raises(FrozenInstanceError):
        assignment.ring = ExecutionRing.RING_0_IN_MEMORY  # type: ignore[misc]
    with pytest.raises(KeyError):
        classifier.classify("surprise-plugin")


def test_invocation_copies_arguments_into_read_only_snapshot():
    source = {"path": "src"}
    call = invocation("repository-reader", arguments=source)
    source["path"] = "/"
    assert call.arguments["path"] == "src"
    with pytest.raises(TypeError):
        call.arguments["path"] = "/"  # type: ignore[index]


def test_chapter_3_denial_happens_before_any_execution_path():
    runtime = RingAwareToolRuntime(
        FakeAuthorizer(False), ToolRingClassifier(SECURE_CODING_ASSIGNMENTS),
        FakeHotPath(), worker(),
    )
    result = asyncio.run(runtime.invoke(invocation("prompt-code-reader")))
    assert result.status == "denied"
    assert result.path == "pre-tool-policy"


def test_ring_zero_uses_hot_path_only():
    runtime = RingAwareToolRuntime(
        FakeAuthorizer(), ToolRingClassifier(SECURE_CODING_ASSIGNMENTS),
        FakeHotPath(), worker(),
    )
    result = asyncio.run(runtime.invoke(invocation("prompt-code-reader", "code:read")))
    assert result.status == "ok"
    assert result.path == "rust-hot-path"


def test_missing_or_erroring_hot_path_denies():
    classifier = ToolRingClassifier(SECURE_CODING_ASSIGNMENTS)
    missing = RingAwareToolRuntime(FakeAuthorizer(), classifier, None, worker())
    assert asyncio.run(missing.invoke(invocation("prompt-code-reader"))).status == "denied"
    error = RingAwareToolRuntime(
        FakeAuthorizer(), classifier, FakeHotPath(HotPathVerdict.ERROR), worker()
    )
    assert asyncio.run(error.invoke(invocation("prompt-code-reader"))).status == "denied"


def test_ring_one_and_two_use_restricted_worker_with_scrubbed_environment(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-parent-secret")
    runtime = RingAwareToolRuntime(
        FakeAuthorizer(), ToolRingClassifier(SECURE_CODING_ASSIGNMENTS),
        FakeHotPath(), worker(),
    )
    for tool in ("repository-reader", "unit-test-runner"):
        result = asyncio.run(runtime.invoke(invocation(tool, arguments={"target": "synthetic"})))
        assert result.status == "ok"
        assert result.path == "restricted-worker"
        assert result.output and result.output["environment_scrubbed"] is True


def test_ring_three_is_denied_pending_human_approval():
    runtime = RingAwareToolRuntime(
        FakeAuthorizer(), ToolRingClassifier(SECURE_CODING_ASSIGNMENTS),
        FakeHotPath(), worker(),
    )
    result = asyncio.run(runtime.invoke(invocation("production-deployer", "production:deploy")))
    assert result.status == "denied"
    assert result.path == "human-approval-required"


def test_oversized_worker_payload_is_rejected():
    with pytest.raises(SandboxExecutionError):
        asyncio.run(
            worker().execute(
                "repository-reader", ExecutionRing.RING_1_LOCAL_RESTRICTED,
                {"value": "x" * (65 * 1024)}, "corr-test",
            )
        )


def test_missing_rust_library_fails_at_initialization(tmp_path):
    with pytest.raises(FileNotFoundError):
        RustHotPathClient(tmp_path / "missing.dylib")
