"""Chapter 4 routing demo. Requires the Rust library for Ring 0."""

import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from governance.hot_path import RustHotPathClient
from governance.ring_runtime import RingAwareToolRuntime
from governance.rings import SECURE_CODING_ASSIGNMENTS, ToolInvocation, ToolRingClassifier
from governance.sandbox import RestrictedWorkerExecutor
from governed_agent_demo import create_context, create_runner


def native_library(root: Path) -> Path:
    names = {
        "darwin": "libhot_path_evaluator.dylib",
        "linux": "libhot_path_evaluator.so",
        "win32": "hot_path_evaluator.dll",
    }
    return root / "hot_path_evaluator" / "target" / "release" / names[sys.platform]


async def main() -> None:
    root = Path(__file__).resolve().parents[1]
    runtime = RingAwareToolRuntime(
        create_runner(),
        ToolRingClassifier(SECURE_CODING_ASSIGNMENTS),
        RustHotPathClient(native_library(root)),
        RestrictedWorkerExecutor(Path(__file__).with_name("sandbox_worker.py")),
    )
    context = create_context()
    calls = (
        ToolInvocation(context, "prompt-code-reader", "code:read", {"length": 120}),
        ToolInvocation(context, "repository-reader", "repo:read", {"path": "synthetic"}),
        ToolInvocation(context, "production-deployer", "production:deploy", {}),
    )
    for call in calls:
        print(json.dumps(asdict(await runtime.invoke(call)), indent=2))


if __name__ == "__main__":
    asyncio.run(main())
