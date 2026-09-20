"""The fuzz harnesses under fuzz/ are runnable without atheris and their corpora replay clean.

Each harness exposes ``test_one_input(data, provider)``; here the provider is the deterministic
``SeedProvider`` from ``fuzz/_support.py``, so every committed corpus file and a fixed set of
byte patterns exercise the same properties the coverage-guided job in self-test.yml enforces on
Linux. A property that regresses fails here first, on every Python in the matrix. The file
layout the CI job relies on -- one corpus directory per harness, every harness listed nowhere
by hand -- is checked from the files themselves.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
FUZZ = REPO / "fuzz"
HARNESSES = sorted(p for p in FUZZ.glob("fuzz_*.py"))
SELF_TEST = REPO / ".github" / "workflows" / "self-test.yml"

# Byte patterns every harness must digest: empty, valid and invalid JSON, non-UTF-8, a list
# file, a path with a form feed (the separator str.splitlines would split on), long input.
PATTERNS = (
    b"",
    b"{}",
    b"[]",
    b"[1]",
    b"null",
    b'"x"',
    b'{"runs": [1], "results": [1], "tools": [], "overlays": 3}',
    b"\xff\xfe\x00",
    b"ALL\n",
    b"a.py\nsub/b.ts\n",
    b"a\x0cb\n",
    b"\x00" * 64,
    b"\xff" * 64,
    bytes(range(256)),
    b"x" * 4096,
    b"[" * 100000,  # nested past the interpreter's stack: json.loads raises RecursionError
    b'{"runs":' * 20000,
)


def _load(path: Path):
    if str(FUZZ) not in sys.path:
        sys.path.insert(0, str(FUZZ))
    return importlib.import_module(path.stem)


def test_there_are_harnesses_and_scorecard_can_see_them():
    assert HARNESSES, "fuzz/ has no fuzz_*.py harness"
    # OpenSSF Scorecard's Fuzzing check looks for a *.py file containing `import atheris`.
    assert any("import atheris" in p.read_text(encoding="utf-8") for p in FUZZ.glob("*.py"))


@pytest.mark.parametrize("harness", HARNESSES, ids=lambda p: p.stem)
def test_every_harness_has_a_corpus_the_ci_job_can_find(harness: Path):
    corpus = FUZZ / "corpus" / harness.stem[len("fuzz_") :]
    assert corpus.is_dir(), f"{harness.name} has no corpus directory at {corpus}"
    assert any(p.is_file() for p in corpus.iterdir()), f"{corpus} is empty"


def test_ci_runs_every_harness_by_glob():
    text = SELF_TEST.read_text(encoding="utf-8")
    assert "for harness in fuzz/fuzz_*.py" in text
    assert 'corpus="fuzz/corpus/${name#fuzz_}"' in text
    assert "requirements-fuzz.txt" in text


@pytest.mark.parametrize("harness", HARNESSES, ids=lambda p: p.stem)
def test_corpus_and_patterns_replay_without_a_violation(harness: Path):
    module = _load(harness)
    corpus = FUZZ / "corpus" / harness.stem[len("fuzz_") :]
    inputs = [p.read_bytes() for p in sorted(corpus.iterdir()) if p.is_file()] + list(PATTERNS)
    for data in inputs:
        module.test_one_input(data)  # raises _support.Violation or the offending exception


def test_the_seed_provider_is_deterministic_and_never_runs_dry():
    support = _load(FUZZ / "_support.py")
    a, b = support.SeedProvider(b"\x01\x02\x03"), support.SeedProvider(b"\x01\x02\x03")
    assert [a.ConsumeIntInRange(0, 9) for _ in range(5)] == [
        b.ConsumeIntInRange(0, 9) for _ in range(5)
    ]
    empty = support.SeedProvider(b"")
    assert empty.ConsumeBool() is False
    assert empty.ConsumeIntInRange(3, 9) == 3
    assert empty.ConsumeUnicodeNoSurrogates(8) == ""
    assert empty.ConsumeFloat() == 0.0
    assert empty.PickValueInList(["first", "second"]) == "first"


def test_mutate_tolerates_an_empty_key_set():
    """``mutate`` must never index into an empty *keys*: with the provider exhausted every
    ``ConsumeBool`` is ``False``, which is exactly the path that used to reach
    ``PickValueInList([])``. The dict-add branch has to fall back to a generated name."""
    support = _load(FUZZ / "_support.py")
    # Bytes chosen so the walk stops at the root dict and the op selects "add a key" (op == 2):
    # a fixed prefix drives the descent depth and op, then the provider runs dry.
    seed = bytes([0x01, 0x00, 0x02])
    for data in (seed, seed + b"\xff" * 16, b""):
        fdp = support.SeedProvider(data)
        out = support.mutate(fdp, {"a": 1, "b": [1, 2]}, keys=[], rounds=8)
        assert isinstance(out, dict)
