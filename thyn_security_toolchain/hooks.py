"""Thin, opinionated wrappers around each pinned scanner.

Every wrapper returns parsed :class:`~thyn_security_toolchain.gate.Finding` objects so
that a single gate (baseline ratchet, annotations, summary) serves the pre-commit
hooks, the pre-push hooks and the CI job alike.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path

from .changed import ZERO_SHA
from .fetch import offline, rules_path, tool_path
from .gate import PARSERS, Finding, demote_low_confidence_levels
from .lock import DATA_DIR
from .repo import DEFAULT_SKIP_DIRS, gitleaks_config, local_opengrep_rules

OVERLAYS_PATH = DATA_DIR / "opengrep-overlays.json"
OPENGREP_TIMEOUT_SECONDS = "10"
OPENGREP_TIMEOUT_THRESHOLD = "3"
OPENGREP_MAX_TARGET_BYTES = "1000000"

# Test code is out of Opengrep's scope by default. What SAST finds there is the fixture, not
# a defect: a hard-coded JWT secret that mints test tokens, jwt.decode(verify=False) on a
# token the test itself just signed, XML parsing of a checked-in sample, subprocess in a test
# harness -- 18 of thyn-ai/algenta's 42 open Opengrep alerts sat under tests/. Opengrep's own
# default .semgrepignore skips tests/ and test/, but a repository that ships its own
# .semgrepignore replaces that default, and files named on the command line (the
# opengrep-changed hook, a PR-scoped CI scan) bypass it -- hence --force-exclude below.
# gitignore syntax, which is what --exclude takes and what the probe on opengrep 1.30.0
# confirmed: src/testing.py, src/tests_helper.py, pkg/test_utils/x.py, src/latest.py stay in;
# benchmarks/ and scripts/ are real code and stay in. Matched relative to the project root, so
# a clone that itself lives under a directory named tests/ or fixtures/ is unaffected.
# The opt-in (scan_tests) lifts exactly this list; Opengrep's built-in default .semgrepignore
# still skips tests/ and test/ on a directory walk until the repository commits a
# .semgrepignore of its own (an empty one is enough -- probed on 1.30.0).
OPENGREP_TEST_PATH_GLOBS = (
    "**/tests/**",
    "**/test/**",
    "**/__tests__/**",
    "**/test_*.py",
    "**/*_test.py",
    "**/conftest.py",
    "**/*.test.ts",
    "**/*.test.tsx",
    "**/*.spec.ts",
    "**/*.spec.tsx",
    "**/*.test.js",
    "**/*.spec.js",
    "**/testdata/**",
    "**/fixtures/**",
)


class ScanError(RuntimeError):
    pass


def _log(msg: str) -> None:
    print(f"[thyn-sec] {msg}", file=sys.stderr)


def _run(
    cmd: Sequence[str],
    cwd: Path,
    ok: Sequence[int] = (0,),
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    if os.environ.get("THYN_SEC_VERBOSE"):
        _log("$ " + " ".join(shlex.quote(str(c)) for c in cmd))
    proc = subprocess.run(
        [str(c) for c in cmd],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
    )
    if proc.returncode not in ok:
        raise ScanError(
            f"{Path(str(cmd[0])).name} exited {proc.returncode}\n"
            f"--- stdout (tail) ---\n{proc.stdout[-4000:]}\n"
            f"--- stderr (tail) ---\n{proc.stderr[-4000:]}"
        )
    return proc


# ----------------------------------------------------------------------------- overlays


@lru_cache(maxsize=1)
def load_overlays() -> dict[str, dict[str, object]]:
    with OVERLAYS_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)["overlays"]


def overlay_names() -> list[str]:
    return sorted(load_overlays())


def resolve_overlay(name: str) -> tuple[list[str], list[str]]:
    """Return ``(packs, exclude_rules)`` for *name*, following ``extends`` transitively."""
    overlays = load_overlays()
    if name not in overlays:
        raise ScanError(f"unknown opengrep overlay {name!r}; known: {', '.join(overlay_names())}")
    packs: list[str] = []
    excludes: list[str] = []
    seen: set = set()

    def visit(n: str) -> None:
        if n in seen:
            return
        seen.add(n)
        spec = overlays[n]
        for parent in spec.get("extends", []) or []:
            visit(str(parent))
        for p in spec.get("packs", []) or []:
            if p not in packs:
                packs.append(str(p))
        for r in spec.get("exclude_rules", []) or []:
            if r not in excludes:
                excludes.append(str(r))

    visit(name)
    return packs, excludes


def opengrep_configs(root: Path, overlay: str) -> tuple[list[Path], list[str]]:
    packs, excludes = resolve_overlay(overlay)
    bundle = rules_path()
    configs: list[Path] = []
    for pack in packs:
        p = bundle / pack
        if p.is_dir():
            configs.append(p)
        else:
            _log(f"warning: overlay {overlay!r} references missing rule pack {pack!r}; skipped")
    configs.extend(local_opengrep_rules(root))
    return configs, excludes


# ----------------------------------------------------------------------------- gitleaks


def push_log_opts() -> str:
    """``git log`` options covering exactly the commits about to be pushed."""
    frm = os.environ.get("PRE_COMMIT_FROM_REF", "")
    to = os.environ.get("PRE_COMMIT_TO_REF", "") or "HEAD"
    if frm and frm != ZERO_SHA:
        return f"{frm}..{to}"
    # New branch: everything not already on any remote.
    return f"{to} --not --remotes"


def gitleaks(root: Path, scope: str, report: Path, log_opts: str | None = None) -> list[Finding]:
    exe = tool_path("gitleaks")
    cfg = gitleaks_config(root)
    report.parent.mkdir(parents=True, exist_ok=True)
    common = [
        "--no-banner",
        "--redact",
        "--exit-code",
        "1",
        "-c",
        str(cfg),
        "-i",
        str(root),
        "-f",
        "json",
        "-r",
        str(report),
    ]
    if scope == "staged":
        cmd = [exe, "git", "--pre-commit", "--staged", *common, str(root)]
    elif scope == "push":
        cmd = [exe, "git", "--log-opts", log_opts or push_log_opts(), *common, str(root)]
    elif scope == "dir":
        cmd = [exe, "dir", str(root), *common]
    else:
        raise ScanError(f"unknown gitleaks scope {scope!r}")
    _run(cmd, root, ok=(0, 1))
    if not report.is_file():
        return []
    return PARSERS["gitleaks"](report, root)


# ----------------------------------------------------------------------------- opengrep


def opengrep_excludes(scan_tests: bool = False) -> list[str]:
    """Every ``--exclude`` pattern an Opengrep run gets.

    The org-wide skip directories always; the test-path globs unless the caller opted into
    scanning tests (``opengrep_scan_tests: true`` / ``--opengrep-scan-tests`` / ``--scan-tests``).
    """
    patterns = list(DEFAULT_SKIP_DIRS)
    if not scan_tests:
        patterns.extend(OPENGREP_TEST_PATH_GLOBS)
    return patterns


def describe_test_paths() -> str:
    """The test-path policy as one line for summaries, derived from the globs themselves."""
    return ", ".join(g[len("**/") :] for g in OPENGREP_TEST_PATH_GLOBS)


def opengrep(
    root: Path,
    overlay: str,
    targets: list[str] | None,
    report: Path,
    scan_tests: bool = False,
) -> list[Finding]:
    """Run Opengrep over *targets* (``None`` = whole repo) and parse the SARIF.

    Test paths (:data:`OPENGREP_TEST_PATH_GLOBS`) are excluded unless *scan_tests*. The
    exclusion is applied by the scanner itself, so the results never exist -- not for the
    gate, not for the code-scanning upload -- and ``--force-exclude`` makes it hold for files
    named explicitly (pre-commit, PR scope) exactly as for a directory walk. The same flag
    makes :data:`~thyn_security_toolchain.repo.DEFAULT_SKIP_DIRS` apply to explicit targets
    too, which is what a full scan already did.
    """
    if targets is not None and not targets:
        return []
    exe = tool_path("opengrep")
    configs, exclude_rules = opengrep_configs(root, overlay)
    if not configs:
        raise ScanError(f"overlay {overlay!r} resolved to zero rule packs")
    report.parent.mkdir(parents=True, exist_ok=True)
    cmd: list[str] = [
        str(exe),
        "scan",
        "--quiet",
        "--no-rewrite-rule-ids",
        "--timeout",
        OPENGREP_TIMEOUT_SECONDS,
        "--timeout-threshold",
        OPENGREP_TIMEOUT_THRESHOLD,
        "--max-target-bytes",
        OPENGREP_MAX_TARGET_BYTES,
        "--sarif-output",
        str(report),
    ]
    for pattern in opengrep_excludes(scan_tests):
        cmd += ["--exclude", pattern]
    # By default Opengrep applies --exclude only to files it discovers itself; a file passed on
    # the command line would slip past every pattern above (opengrep 1.30.0, verified).
    cmd.append("--force-exclude")
    for c in configs:
        cmd += ["--config", str(c)]
    for r in exclude_rules:
        cmd += ["--exclude-rule", r]
    cmd += targets if targets is not None else ["."]
    _run(cmd, root, ok=(0, 1))
    if report.is_file():
        demote_low_confidence_levels(report)
    return PARSERS["opengrep"](report, root) if report.is_file() else []


# ----------------------------------------------------------------------------- osv-scanner

OSV_EXIT_NO_PACKAGES = 128


def osv(root: Path, report: Path) -> list[Finding]:
    exe = tool_path("osv-scanner")
    report.parent.mkdir(parents=True, exist_ok=True)
    cmd: list[str] = [
        str(exe),
        "scan",
        "source",
        "--recursive",
        "--format",
        "json",
        "--output-file",
        str(report),
        "--verbosity",
        "error",
    ]
    for d in DEFAULT_SKIP_DIRS:
        cmd += ["--experimental-exclude", d]
    cfg = root / "osv-scanner.toml"
    if cfg.is_file():
        cmd += ["--config", str(cfg)]
    if offline() or os.environ.get("THYN_SEC_OSV_OFFLINE", "").lower() in ("1", "true", "yes"):
        cmd.append("--offline-vulnerabilities")
    cmd.append(str(root))
    proc = _run(cmd, root, ok=(0, 1, OSV_EXIT_NO_PACKAGES))
    if proc.returncode == OSV_EXIT_NO_PACKAGES or not report.is_file():
        return []
    return PARSERS["osv"](report, root)


def osv_download_offline_db(root: Path) -> None:
    exe = tool_path("osv-scanner")
    _run(
        [
            exe,
            "scan",
            "source",
            "--recursive",
            "--download-offline-databases",
            "--offline-vulnerabilities",
            "--format",
            "json",
            "--output-file",
            os.devnull,
            str(root),
        ],
        root,
        ok=(0, 1, OSV_EXIT_NO_PACKAGES),
    )


# ------------------------------------------------------------------- trivy (config mode only)


def trivy(root: Path, report: Path) -> list[Finding]:
    exe = tool_path("trivy")
    report.parent.mkdir(parents=True, exist_ok=True)
    cmd: list[str] = [
        str(exe),
        "config",
        "--quiet",
        "--format",
        "sarif",
        "--output",
        str(report),
        "--severity",
        "HIGH,CRITICAL",
        "--exit-code",
        "0",
        "--skip-dirs",
        ",".join(f"**/{d}" for d in DEFAULT_SKIP_DIRS),
    ]
    ignore = root / ".trivyignore"
    if ignore.is_file():
        cmd += ["--ignorefile", str(ignore)]
    cfg = root / "trivy.yaml"
    if cfg.is_file():
        cmd += ["--config", str(cfg)]
    env: dict[str, str] = {}
    if offline():
        env["TRIVY_SKIP_CHECK_UPDATE"] = "true"
    cmd.append(str(root))
    _run(cmd, root, env=env)
    return PARSERS["trivy"](report, root) if report.is_file() else []


# ----------------------------------------------------------------------------- actionlint


def actionlint(root: Path, files: Sequence[str]) -> int:
    if not files:
        return 0
    exe = tool_path("actionlint")
    proc = subprocess.run([str(exe), *files], cwd=str(root), text=True)
    return proc.returncode
