"""Bounded subprocess executor for Ring 1 and Ring 2 mock tools."""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from .rings import ExecutionRing


class SandboxExecutionError(RuntimeError):
    pass


class RestrictedWorkerExecutor:
    MAX_PAYLOAD_BYTES = 64 * 1024
    MAX_OUTPUT_BYTES = 64 * 1024

    def __init__(
        self,
        worker_path: str | Path,
        *,
        allowed_rings: frozenset[ExecutionRing] = frozenset(
            {ExecutionRing.RING_1_LOCAL_RESTRICTED, ExecutionRing.RING_2_UNTRUSTED_OR_EXTERNAL}
        ),
        timeout_seconds: float = 2.0,
        max_concurrency: int = 4,
    ) -> None:
        self._worker = Path(worker_path).resolve(strict=True)
        if timeout_seconds <= 0:
            raise ValueError("Worker timeout must be positive")
        if max_concurrency <= 0:
            raise ValueError("Worker concurrency must be positive")
        self._allowed_rings = allowed_rings
        self._timeout = timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def execute(
        self,
        tool_name: str,
        ring: ExecutionRing,
        arguments: Mapping[str, Any],
        correlation_id: str,
    ) -> dict[str, Any]:
        if ring not in self._allowed_rings:
            raise SandboxExecutionError(f"Ring {ring.name} is not permitted in the worker")
        payload = json.dumps(
            {"tool": tool_name, "arguments": dict(arguments), "correlation_id": correlation_id}
        ).encode("utf-8")
        if len(payload) > self.MAX_PAYLOAD_BYTES:
            raise SandboxExecutionError("Worker payload exceeds the 64 KiB limit")

        async with self._semaphore:
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-I",
                str(self._worker),
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={},
                close_fds=True,
                limit=self.MAX_OUTPUT_BYTES + 1,
            )
            try:
                assert process.stdin is not None
                assert process.stdout is not None
                assert process.stderr is not None
                process.stdin.write(payload)
                await process.stdin.drain()
                process.stdin.close()
                await process.stdin.wait_closed()
                stdout, stderr, _ = await asyncio.wait_for(
                    asyncio.gather(
                        self._read_limited(process.stdout),
                        self._read_limited(process.stderr),
                        process.wait(),
                    ),
                    timeout=self._timeout,
                )
            except (asyncio.TimeoutError, SandboxExecutionError) as exc:
                process.kill()
                await process.wait()
                if isinstance(exc, asyncio.TimeoutError):
                    raise SandboxExecutionError("Worker timed out and was terminated") from exc
                raise
            except asyncio.CancelledError:
                process.kill()
                await process.wait()
                raise

        if len(stdout) > self.MAX_OUTPUT_BYTES or len(stderr) > self.MAX_OUTPUT_BYTES:
            raise SandboxExecutionError("Worker output exceeded the 64 KiB limit")
        if process.returncode != 0:
            raise SandboxExecutionError("Worker rejected the invocation")
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise SandboxExecutionError("Worker returned invalid JSON") from exc
        if not isinstance(result, dict) or result.get("status") != "ok":
            raise SandboxExecutionError("Worker did not return an explicit success result")
        if result.get("correlation_id") != correlation_id or result.get("tool") != tool_name:
            raise SandboxExecutionError("Worker result binding did not match the request")
        return result

    async def _read_limited(self, stream: asyncio.StreamReader) -> bytes:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await stream.read(min(8192, self.MAX_OUTPUT_BYTES + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > self.MAX_OUTPUT_BYTES:
                raise SandboxExecutionError("Worker output exceeded the 64 KiB limit")
