"""Safe ctypes binding for the Rust Ring 0 evaluator."""

import ctypes
from enum import IntEnum
from pathlib import Path


class HotPathVerdict(IntEnum):
    ALLOW = 0
    DENY = 1
    ERROR = 2


class _HotPathRequest(ctypes.Structure):
    _fields_ = [
        ("tool_name", ctypes.c_char_p),
        ("ring", ctypes.c_int),
        ("principal_id", ctypes.c_char_p),
    ]


class RustHotPathClient:
    def __init__(self, library_path: str | Path) -> None:
        path = Path(library_path).expanduser().resolve(strict=True)
        if path.suffix not in {".dylib", ".so", ".dll"}:
            raise ValueError("Hot-path library has an unexpected file extension")
        self._library = ctypes.CDLL(str(path))
        evaluator = self._library.evaluate_hot_path
        evaluator.argtypes = [_HotPathRequest]
        evaluator.restype = ctypes.c_int
        self._evaluate = evaluator

    def evaluate(self, tool_name: str, ring: int, principal_id: str) -> HotPathVerdict:
        try:
            raw = self._evaluate(
                _HotPathRequest(
                    tool_name.encode("utf-8"), ring, principal_id.encode("utf-8")
                )
            )
            return HotPathVerdict(raw)
        except Exception:
            return HotPathVerdict.ERROR
