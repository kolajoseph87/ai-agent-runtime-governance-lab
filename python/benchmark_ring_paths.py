"""Measure local Ring 0 FFI and restricted-worker overhead separately."""

import asyncio
import statistics
import sys
import time
from pathlib import Path

from governance.hot_path import RustHotPathClient
from governance.rings import ExecutionRing
from governance.sandbox import RestrictedWorkerExecutor


def library_path(root: Path) -> Path:
    name = {
        "darwin": "libhot_path_evaluator.dylib",
        "linux": "libhot_path_evaluator.so",
        "win32": "hot_path_evaluator.dll",
    }[sys.platform]
    return root / "hot_path_evaluator" / "target" / "release" / name


async def main() -> None:
    root = Path(__file__).resolve().parents[1]
    hot_path = RustHotPathClient(library_path(root))
    worker = RestrictedWorkerExecutor(Path(__file__).with_name("sandbox_worker.py"))

    hot_samples: list[float] = []
    for _ in range(1_000):
        start = time.perf_counter_ns()
        hot_path.evaluate("prompt-code-reader", 0, "developer-benchmark")
        hot_samples.append((time.perf_counter_ns() - start) / 1_000)

    worker_samples: list[float] = []
    for index in range(25):
        start = time.perf_counter_ns()
        await worker.execute(
            "repository-reader", ExecutionRing.RING_1_LOCAL_RESTRICTED,
            {"path": "synthetic"}, f"corr-benchmark-{index}",
        )
        worker_samples.append((time.perf_counter_ns() - start) / 1_000_000)

    print(f"Rust FFI median: {statistics.median(hot_samples):.3f} microseconds")
    print(f"Worker median: {statistics.median(worker_samples):.3f} milliseconds")
    print("These are measurements from this machine, not universal performance claims.")


if __name__ == "__main__":
    asyncio.run(main())
