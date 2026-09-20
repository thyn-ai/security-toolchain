"""Pin consistency: hooks, CI caller and installed toolchain must agree on one version.

Regex-only on purpose (no YAML dependency): the two shapes we care about are fixed by
our own templates.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import __version__
from .lock import load_lock

REPO_URL = "https://github.com/thyn-ai/security-toolchain"
BLOCK_BEGIN = "# thyn-security-toolchain:begin"
BLOCK_END = "# thyn-security-toolchain:end"

_REV_RE = re.compile(r"^\s*rev:\s*['\"]?([^'\"\s#]+)", re.M)
_USES_RE = re.compile(
    r"uses:\s*thyn-ai/security-toolchain/\.github/workflows/([\w.-]+\.ya?ml)@([^\s#]+)"
    r"[ \t]*(?:#[ \t]*([^\s]+))?"
)
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# The reusable workflows that scan a checkout; a pin on any other workflow of this repository is
# verified the same way but does not stand in for the gate.
GATE_WORKFLOWS = frozenset({"security-full.yml", "security-smoke.yml"})
_HOOK_TYPES_RE = re.compile(r"^default_install_hook_types:\s*\[([^\]]*)\]", re.M)


def installed_tag() -> str:
    return f"v{__version__}"


def precommit_rev(config_text: str) -> str | None:
    idx = config_text.find(f"repo: {REPO_URL}")
    if idx < 0:
        return None
    m = _REV_RE.search(config_text, idx)
    return m.group(1) if m else None


def caller_pins(workflow_text: str) -> list[tuple[str, str, str | None]]:
    """Return ``(workflow file, ref, comment tag)`` for every call into this toolchain.

    Lines that are YAML comments are documentation, not calls, and are skipped.
    """
    pins: list[tuple[str, str, str | None]] = []
    for line in workflow_text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for m in _USES_RE.finditer(line):
            pins.append((m.group(1), m.group(2), m.group(3)))
    return pins


def verify_repo(root: Path, expect_ref: str | None = None) -> list[str]:
    problems: list[str] = []
    load_lock()  # raises LockError on a malformed lock

    tag = installed_tag()
    pc = root / ".pre-commit-config.yaml"
    rev: str | None = None
    if pc.is_file():
        text = pc.read_text(encoding="utf-8")
        rev = precommit_rev(text)
        if rev is not None:
            if rev != tag:
                problems.append(
                    f".pre-commit-config.yaml pins rev {rev} but the installed toolchain is {tag}"
                )
            m = _HOOK_TYPES_RE.search(text)
            types = [t.strip().strip("'\"") for t in (m.group(1).split(",") if m else [])]
            if "pre-push" not in types:
                problems.append(
                    ".pre-commit-config.yaml lacks "
                    "`default_install_hook_types: [pre-commit, pre-push]`; "
                    "the pre-push gate would never be installed"
                )

    calls: list[tuple[Path, str, str, str | None]] = []
    wf_dir = root / ".github" / "workflows"
    if wf_dir.is_dir():
        for wf in sorted(wf_dir.glob("*.yml")) + sorted(wf_dir.glob("*.yaml")):
            for name, ref, comment in caller_pins(wf.read_text(encoding="utf-8")):
                calls.append((wf, name, ref, comment))

    for wf, name, ref, comment in calls:
        where = f"{wf.relative_to(root)} -> {name}"
        if not _SHA_RE.match(ref):
            problems.append(
                f"{where} is pinned to {ref!r}; pin a 40-hex commit SHA with a `# vX.Y.Z` comment"
            )
        if comment is None:
            problems.append(f"{where} has no `# vX.Y.Z` version comment after the SHA")
        elif comment != tag:
            problems.append(f"{where} comment says {comment} but the installed toolchain is {tag}")
        if expect_ref:
            if _SHA_RE.match(expect_ref):
                if ref != expect_ref:
                    problems.append(f"{where} SHA {ref} != checked-out toolchain {expect_ref}")
            elif comment and comment != expect_ref:
                problems.append(
                    f"{where} comment {comment} != checked-out toolchain ref {expect_ref}"
                )

    # The two cross-checks below are about the security gate: the Dependabot auto-merge caller
    # pins the toolchain too (checked above like any other pin) but scans nothing.
    gates = [c for c in calls if c[1] in GATE_WORKFLOWS]
    if gates and rev is None and pc.is_file():
        problems.append(
            "CI calls the toolchain but .pre-commit-config.yaml has no "
            "thyn-ai/security-toolchain block; developers would only learn about findings "
            "after pushing"
        )
    if rev is not None and not gates and wf_dir.is_dir():
        problems.append(
            "pre-commit uses the toolchain but no workflow calls security-full/security-smoke; "
            "nothing re-checks a clean checkout"
        )
    return problems
