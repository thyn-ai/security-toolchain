"""Fuzz the ``toolchain.lock`` validator, the trust root for every binary the toolchain runs.

Property: for any JSON document, :func:`thyn_security_toolchain.lock.validate_lock` either
returns (the lock is usable) or raises :class:`~thyn_security_toolchain.lock.LockError` -- never
an ``AttributeError``, ``TypeError`` or ``KeyError`` from a field of the wrong shape. A lock the
validator accepts must satisfy what the rest of the package assumes about it: every tool has a
non-empty version string and, per platform, a ``https://github.com/`` asset URL naming that
version and a 64-hex sha256; every rules bundle has ``commit``, ``url`` and a 64-hex sha256.

Two inputs per iteration: the raw bytes as a lock file (unparsable JSON must be a
``ValueError``), and a structure-aware mutation of the shipped lock so the fuzzer spends its
time near the accepted shape instead of on JSON syntax.

Run: ``python fuzz/fuzz_lock.py fuzz/corpus/lock -max_total_time=60``
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _support import SeedProvider, check, json_value, mutate, run_main  # noqa: E402

from thyn_security_toolchain import lock  # noqa: E402

SHIPPED = json.loads(lock.LOCK_PATH.read_text(encoding="utf-8"))
KEYS = (
    "schema",
    "tools",
    "rules",
    "version",
    "assets",
    "url",
    "sha256",
    "archive",
    "member",
    "commit",
    *lock.TOOLS,
    *lock.PLATFORMS,
    "opengrep-rules",
)
HEX = set("0123456789abcdef")


def _accepted_lock_is_complete(doc: dict[str, Any]) -> None:
    check(doc.get("schema") == 1, "accepted lock has a schema other than 1")
    for tool in lock.TOOLS:
        spec = doc["tools"][tool]
        version = spec["version"]
        check(isinstance(version, str) and version != "", f"{tool}: accepted empty version")
        for plat in lock.PLATFORMS:
            asset = spec["assets"][plat]
            url = asset["url"]
            check(isinstance(url, str) and url.startswith("https://github.com/"), f"{tool} url")
            check(version in url, f"{tool}/{plat}: accepted url without the version")
            digest = asset["sha256"]
            check(
                isinstance(digest, str) and len(digest) == 64 and set(digest) <= HEX,
                f"{tool}/{plat}: accepted a sha256 that is not 64 lowercase hex chars",
            )
            if asset.get("archive") == "tar.gz":
                check(bool(asset.get("member")), f"{tool}/{plat}: tar.gz without member")
    for name, spec in (doc.get("rules") or {}).items():
        for key in ("commit", "url"):
            check(isinstance(spec[key], str) and spec[key] != "", f"rules {name}: empty {key}")
        digest = spec["sha256"]
        check(
            isinstance(digest, str) and len(digest) == 64 and set(digest) <= HEX,
            f"rules {name}: accepted a bad sha256",
        )


def validate(doc: Any) -> None:
    """validate_lock(doc) must return or raise LockError; an accepted doc must be complete."""
    try:
        lock.validate_lock(doc)
    except lock.LockError:
        return
    _accepted_lock_is_complete(doc)
    # Idempotent: a lock accepted once is accepted again (validation has no side effects).
    lock.validate_lock(doc)


def test_one_input(data: bytes, provider: type = SeedProvider) -> None:
    try:
        raw = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        raw = None  # unparsable bytes (or nested past the stack): nothing more to check
    else:
        validate(raw)

    fdp = provider(data)
    if fdp.ConsumeBool():
        validate(mutate(fdp, SHIPPED, KEYS, rounds=fdp.ConsumeIntInRange(1, 6)))
    else:
        validate(json_value(fdp, KEYS, depth=5))


def main(argv: list[str]) -> None:
    run_main(argv, test_one_input)


if __name__ == "__main__":
    main(sys.argv)
