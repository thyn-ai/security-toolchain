"""Shared pieces of the fuzz harnesses: property checks, a JSON generator, a seed provider.

Each ``fuzz_*.py`` next to this file is an `atheris <https://github.com/google/atheris>`_
entry point (``python fuzz/fuzz_lock.py <corpus dir>``) whose ``test_one_input(data, provider)``
also runs without the fuzzing engine: :class:`SeedProvider` implements the handful of
``FuzzedDataProvider`` methods the harnesses use, so ``tests/test_fuzz_harnesses.py`` replays the
committed corpus on every Python in the matrix while the ``fuzz`` job in ``self-test.yml`` runs
the real engine with coverage guidance on Linux.

Only the standard library is used here; ``import atheris`` lives in each harness's ``main``.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Sequence
from typing import Any, Protocol


class Violation(AssertionError):
    """A property the harness checks did not hold for this input.

    Raised as a plain exception (never ``assert``) so the check survives ``python -O`` and so a
    failure reads as the property that broke, not as a stack trace inside the code under test.
    """


def check(condition: bool, what: str) -> None:
    if not condition:
        raise Violation(what)


class Provider(Protocol):
    """The subset of ``atheris.FuzzedDataProvider`` the harnesses consume."""

    def ConsumeBool(self) -> bool: ...
    def ConsumeIntInRange(self, low: int, high: int) -> int: ...
    def ConsumeUnicodeNoSurrogates(self, count: int) -> str: ...
    def ConsumeBytes(self, count: int) -> bytes: ...
    def ConsumeFloat(self) -> float: ...
    def PickValueInList(self, values: Sequence[Any]) -> Any: ...
    def remaining_bytes(self) -> int: ...


class SeedProvider:
    """A deterministic ``FuzzedDataProvider`` stand-in over one byte string.

    Semantics match atheris where the harnesses rely on them: an exhausted provider yields
    zeros, ``False``, empty strings and the first list element, so any byte string -- including
    an empty one -- drives a harness to completion.
    """

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def remaining_bytes(self) -> int:
        return len(self._data) - self._pos

    def ConsumeBytes(self, count: int) -> bytes:
        chunk = self._data[self._pos : self._pos + count]
        self._pos += len(chunk)
        return chunk

    def ConsumeBool(self) -> bool:
        return bool(self.ConsumeBytes(1)[:1] and self._data[self._pos - 1] & 1)

    def ConsumeIntInRange(self, low: int, high: int) -> int:
        if high <= low:
            return low
        span = high - low + 1
        width = max(1, (span.bit_length() + 7) // 8)
        raw = self.ConsumeBytes(width)
        return low + (int.from_bytes(raw, "little") % span if raw else 0)

    def ConsumeUnicodeNoSurrogates(self, count: int) -> str:
        raw = self.ConsumeBytes(count)
        text = raw.decode("utf-8", errors="replace")
        return "".join(ch for ch in text if not 0xD800 <= ord(ch) <= 0xDFFF)

    def ConsumeFloat(self) -> float:
        raw = self.ConsumeBytes(8)
        if len(raw) < 8:
            return 0.0
        value = struct.unpack("<d", raw)[0]
        return value if value == value and abs(value) != float("inf") else 0.0

    def PickValueInList(self, values: Sequence[Any]) -> Any:
        return values[self.ConsumeIntInRange(0, len(values) - 1)]


# Short strings that appear in real reports: mixing them into generated documents lets the
# fuzzer reach the branches keyed on them (``"error"`` levels, ``GHSA-`` ids, ``file://`` uris)
# without having to discover the byte sequences itself.
INTERESTING_STRINGS = (
    "",
    " ",
    "\n",
    "\x00",
    "./",
    "../",
    "/",
    "file:///",
    "file:///repo/a.py",
    "%SRCROOT%/a.py",
    "a.py",
    "tests/test_a.py",
    "Dockerfile",
    "error",
    "warning",
    "note",
    "LOW CONFIDENCE",
    "HIGH",
    "GHSA-xxxx-xxxx-xxxx",
    "CVE-2024-0001",
    "npm",
    "PyPI",
    "9.8",
    "7.0",
    "4.0",
    "0",
    "-1",
    "1e400",
    "nan",
    "ubuntu:24.04",
    "https://github.com/",
    "x" * 300,
)


def text(fdp: Provider, limit: int = 40) -> str:
    """A short string: sometimes one of the interesting constants, sometimes fuzzer bytes."""
    if fdp.ConsumeBool():
        return fdp.PickValueInList(INTERESTING_STRINGS)
    return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, limit))


def scalar(fdp: Provider) -> Any:
    kind = fdp.ConsumeIntInRange(0, 6)
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeBool()
    if kind == 2:
        return fdp.ConsumeIntInRange(-(2**40), 2**40)
    if kind == 3:
        return fdp.ConsumeFloat()
    return text(fdp)


def json_value(fdp: Provider, keys: Sequence[str], depth: int = 4) -> Any:
    """A JSON-serialisable value biased towards the given *keys* and towards small shapes.

    ``depth`` bounds nesting; ``keys`` are the field names the parser under test looks up, so
    the generated objects are structurally close to a real report with occasional type
    confusion (a list where an object is expected, a number where a string is).
    """
    if depth <= 0 or fdp.ConsumeIntInRange(0, 3) == 0:
        return scalar(fdp)
    if fdp.ConsumeBool():
        return [json_value(fdp, keys, depth - 1) for _ in range(fdp.ConsumeIntInRange(0, 4))]
    obj: dict[str, Any] = {}
    for _ in range(fdp.ConsumeIntInRange(0, 6)):
        key = fdp.PickValueInList(keys) if keys and fdp.ConsumeBool() else text(fdp, 12)
        obj[key] = json_value(fdp, keys, depth - 1)
    return obj


def mutate(fdp: Provider, value: Any, keys: Sequence[str], rounds: int) -> Any:
    """Apply *rounds* random edits to a copy of a real document, keeping most of it intact."""
    import copy

    doc = copy.deepcopy(value)
    for _ in range(rounds):
        _mutate_once(fdp, doc, keys)
    return doc


def _mutate_once(fdp: Provider, node: Any, keys: Sequence[str]) -> None:
    # Descend to a random depth, then replace, delete or add one entry there.
    parent: Any = None
    slot: Any = None
    current = node
    for _ in range(fdp.ConsumeIntInRange(0, 5)):
        if isinstance(current, dict) and current:
            slot = fdp.PickValueInList(sorted(current))
        elif isinstance(current, list) and current:
            slot = fdp.ConsumeIntInRange(0, len(current) - 1)
        else:
            break
        parent, current = current, current[slot]
    if parent is None:
        return
    op = fdp.ConsumeIntInRange(0, 2)
    if op == 0:
        parent[slot] = json_value(fdp, keys, 2)
    elif op == 1 and isinstance(parent, dict):
        del parent[slot]
    elif op == 1:
        del parent[slot]
    elif isinstance(parent, dict):
        # Same guard as ``json_value``: an empty *keys* must fall back to a generated name
        # rather than index into an empty sequence.
        new_key = fdp.PickValueInList(keys) if keys and fdp.ConsumeBool() else text(fdp, 12)
        parent[new_key] = json_value(fdp, keys, 2)
    else:
        parent.insert(fdp.ConsumeIntInRange(0, len(parent)), json_value(fdp, keys, 2))


def run_main(argv: list[str], one_input: Callable[[bytes], None]) -> None:
    """Hand *one_input* to atheris with the standard flags for a bounded, instrumented run."""
    import atheris  # the fuzzing engine; the properties themselves need only the stdlib

    atheris.instrument_all()
    atheris.Setup(argv, one_input)
    atheris.Fuzz()
