"""``thyn-sec`` command line: one subcommand per pre-commit hook, plus CI plumbing."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import __version__, hooks
from . import changed as changed_mod
from .ci import TOOL_ORDER, gate_findings, run_ci
from .fetch import ToolchainError, cache_dir, rules_path, tool_path
from .gate import annotate
from .lock import TOOLS, load_lock
from .repo import existing_files, git_root
from .verify import verify_repo

DEFAULT_OVERLAY = "python-uv"
SCAN_TESTS_HELP = (
    "also run Opengrep over test code (tests/, test/, __tests__/, test_*.py, *_test.py, "
    "conftest.py, *.test.ts|tsx|js, *.spec.ts|tsx|js, testdata/, fixtures/); default: test "
    "paths are out of scope, what SAST finds there is the fixture, not a defect. Lifts this "
    "toolchain's exclusion only: Opengrep's built-in .semgrepignore still skips tests/ and "
    "test/ (on full scans and, because --force-exclude applies it to named files too, on "
    "PR-scoped runs) unless the repository has a .semgrepignore of its own (an empty one is "
    "enough)"
)


def _root(args: argparse.Namespace) -> Path:
    return Path(args.root).resolve() if getattr(args, "root", None) else git_root()


def _tmp_report(suffix: str) -> Path:
    fd, name = tempfile.mkstemp(prefix="thyn-sec-", suffix=suffix)
    os.close(fd)
    return Path(name)


def _local_gate(tool: str, root: Path, findings) -> int:
    # Local hooks always ratchet: with a baseline, only new findings fail; without one they advise.
    result = gate_findings(tool, root, findings, "ratchet")
    annotate(result, stream=sys.stderr)
    return result.exit_code


# ----------------------------------------------------------------------------- hook commands


def cmd_gitleaks_staged(args: argparse.Namespace) -> int:
    root = _root(args)
    findings = hooks.gitleaks(root, "staged", _tmp_report(".json"))
    return _local_gate("gitleaks", root, findings)


def cmd_gitleaks_push(args: argparse.Namespace) -> int:
    root = _root(args)
    findings = hooks.gitleaks(root, "push", _tmp_report(".json"), log_opts=args.log_opts)
    return _local_gate("gitleaks", root, findings)


def cmd_gitleaks_dir(args: argparse.Namespace) -> int:
    root = _root(args)
    findings = hooks.gitleaks(root, "dir", _tmp_report(".json"))
    return _local_gate("gitleaks", root, findings)


def cmd_opengrep_changed(args: argparse.Namespace) -> int:
    root = _root(args)
    files = existing_files(root, args.files)
    if not files:
        return 0
    findings = hooks.opengrep(
        root, args.overlay, files, _tmp_report(".sarif"), scan_tests=args.scan_tests
    )
    return _local_gate("opengrep", root, findings)


def cmd_opengrep_full(args: argparse.Namespace) -> int:
    root = _root(args)
    findings = hooks.opengrep(
        root, args.overlay, None, _tmp_report(".sarif"), scan_tests=args.scan_tests
    )
    return _local_gate("opengrep", root, findings)


def cmd_osv_scan(args: argparse.Namespace) -> int:
    root = _root(args)
    findings = hooks.osv(root, _tmp_report(".json"))
    return _local_gate("osv", root, findings)


def cmd_trivy_config(args: argparse.Namespace) -> int:
    root = _root(args)
    findings = hooks.trivy(root, _tmp_report(".sarif"))
    return _local_gate("trivy", root, findings)


def cmd_actionlint(args: argparse.Namespace) -> int:
    root = _root(args)
    return hooks.actionlint(root, existing_files(root, args.files))


def cmd_verify_toolchain(args: argparse.Namespace) -> int:
    root = _root(args)
    problems = verify_repo(root, expect_ref=args.expect_ref)
    for p in problems:
        print(f"[thyn-sec verify] {p}", file=sys.stderr)
    if not problems:
        print(f"[thyn-sec verify] ok: toolchain v{__version__}, pins consistent", file=sys.stderr)
    return 1 if problems else 0


def cmd_security_fix_deps(args: argparse.Namespace) -> int:
    root = _root(args)
    exe = tool_path("osv-scanner")
    print(
        "osv-scanner's guided remediation is experimental and rewrites lockfiles; it is\n"
        "exposed on purpose as a manual step, never as an automatic hook. Review the diff\n"
        "it produces like any other.\n\n"
        f"  {exe} fix --non-interactive --strategy in-place -L <lockfile>\n"
        "      # e.g. uv.lock, package-lock.json, pnpm-lock.yaml\n"
        f"  {exe} fix --non-interactive --strategy relock  -M <manifest> -L <lockfile>\n\n"
        f"(run from {root})",
        file=sys.stderr,
    )
    return 0


# ----------------------------------------------------------------------------- CI plumbing


def cmd_changed_files(args: argparse.Namespace) -> int:
    changed = changed_mod.changed_files()
    if args.output:
        changed_mod.write_list(changed, Path(args.output))
    else:
        print(changed_mod.ALL if changed_mod.is_all(changed) else "\n".join(changed))
    print(f"[thyn-sec changed-files] scope: {changed_mod.describe(changed)}", file=sys.stderr)
    return 0


def cmd_ci(args: argparse.Namespace) -> int:
    root = _root(args)
    if args.changed is None:
        changed = changed_mod.changed_files()
    elif args.changed.upper() == changed_mod.ALL:
        changed = changed_mod.ALL
    else:
        changed = changed_mod.read_list(args.changed)
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    unknown = [t for t in tools if t not in TOOL_ORDER]
    if unknown:
        raise SystemExit(f"unknown tools {unknown}; choose from {', '.join(TOOL_ORDER)}")
    out_dir = (
        Path(args.out_dir).resolve()
        if args.out_dir
        else Path(tempfile.mkdtemp(prefix="thyn-sec-ci-"))
    )
    return run_ci(
        root,
        args.overlay,
        args.mode,
        changed,
        out_dir,
        tools,
        args.measure_baseline,
        upload_audit=args.opengrep_upload_audit,
        scan_tests=args.opengrep_scan_tests,
    )


def cmd_install(args: argparse.Namespace) -> int:
    names = list(TOOLS) if args.tool == "all" else [args.tool]
    for name in names:
        path = tool_path(name)
        print(
            f"{name}\t{path}" if args.print_path else f"[thyn-sec] {name} ready at {path}",
            file=sys.stdout,
        )
    if args.rules or args.tool == "all":
        print(
            f"opengrep-rules\t{rules_path()}"
            if args.print_path
            else f"[thyn-sec] opengrep-rules ready at {rules_path()}"
        )
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    import subprocess

    exe = tool_path(args.tool)
    return subprocess.run([str(exe), *args.args]).returncode


def cmd_lock(args: argparse.Namespace) -> int:
    import json

    lock = load_lock()
    if args.json:
        print(json.dumps(lock, indent=2))
        return 0
    print(f"thyn-security-toolchain v{__version__}  cache: {cache_dir()}")
    for name, spec in lock["tools"].items():
        print(f"  {name:<12} {spec['version']:<10} {spec.get('verification', '')}")
    for name, spec in lock.get("rules", {}).items():
        print(f"  {name:<12} {spec['commit'][:12]:<10} {spec.get('license', '')}")
    return 0


def cmd_overlays(args: argparse.Namespace) -> int:
    for name in hooks.overlay_names():
        packs, excl = hooks.resolve_overlay(name)
        print(f"{name}: {len(packs)} packs" + (f", excludes {excl}" if excl else ""))
        if args.verbose:
            for p in packs:
                print(f"    {p}")
    return 0


# ----------------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="thyn-sec", description=__doc__)
    parser.add_argument("--version", action="version", version=f"thyn-sec {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name: str, func, help_: str, **kw) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_, **kw)
        p.add_argument("--root", help="repository root (default: git toplevel of the cwd)")
        p.set_defaults(func=func)
        return p

    add("gitleaks-staged", cmd_gitleaks_staged, "scan staged changes for secrets (pre-commit)")
    p = add(
        "gitleaks-push",
        cmd_gitleaks_push,
        "scan the commits about to be pushed for secrets (pre-push)",
    )
    p.add_argument(
        "--log-opts", help="override the git log range (default: derived from pre-commit env)"
    )
    add("gitleaks-dir", cmd_gitleaks_dir, "scan the working tree for secrets (CI smoke)")

    p = add("opengrep-changed", cmd_opengrep_changed, "SAST over the given files (pre-commit)")
    p.add_argument("--overlay", default=DEFAULT_OVERLAY)
    p.add_argument("--scan-tests", action="store_true", help=SCAN_TESTS_HELP)
    p.add_argument("files", nargs="*")
    p = add(
        "opengrep-full",
        cmd_opengrep_full,
        "SAST over the whole repo vs security/baseline/opengrep.txt (pre-push)",
    )
    p.add_argument("--overlay", default=DEFAULT_OVERLAY)
    p.add_argument("--scan-tests", action="store_true", help=SCAN_TESTS_HELP)

    add(
        "osv-scan",
        cmd_osv_scan,
        "dependency vulnerabilities vs security/baseline/osv.txt (pre-push)",
    )
    add(
        "trivy-config",
        cmd_trivy_config,
        "IaC misconfiguration vs security/baseline/trivy.txt (pre-push)",
    )

    p = add("actionlint", cmd_actionlint, "lint GitHub Actions workflow files")
    p.add_argument("files", nargs="*")

    p = add(
        "verify-toolchain",
        cmd_verify_toolchain,
        "check hook rev, CI SHA pin and installed version agree",
    )
    p.add_argument("--expect-ref", help="the toolchain ref CI checked out (tag or SHA)")

    add(
        "security-fix-deps",
        cmd_security_fix_deps,
        "print osv-scanner guided-remediation commands (manual)",
    )

    p = add(
        "changed-files",
        cmd_changed_files,
        "derive the PR/push changed-file list (fail-closed to ALL)",
    )
    p.add_argument("--output", help="write the list to this file instead of stdout")

    p = add(
        "ci", cmd_ci, "run every owner tool once and gate against baselines (the authoritative job)"
    )
    p.add_argument("--overlay", default=DEFAULT_OVERLAY)
    p.add_argument("--mode", choices=("advisory", "ratchet"), default="advisory")
    p.add_argument(
        "--changed", help="path to a changed-files list, or ALL (default: derive from the event)"
    )
    p.add_argument("--out-dir", help="directory for reports and summary.md")
    p.add_argument("--tools", default=",".join(TOOL_ORDER), help="comma list of tools to run")
    p.add_argument(
        "--measure-baseline", action="store_true", help="write security/baseline/*.txt (CI only)"
    )
    p.add_argument(
        "--opengrep-upload-audit",
        action="store_true",
        help="also hand Opengrep audit / low-confidence results to code scanning "
        "(default: console summary and reports artifact only)",
    )
    p.add_argument("--opengrep-scan-tests", action="store_true", help=SCAN_TESTS_HELP)

    p = add("install", cmd_install, "fetch and verify pinned binaries into the cache")
    p.add_argument("tool", choices=(*TOOLS, "all"))
    p.add_argument("--rules", action="store_true", help="also fetch the opengrep rules bundle")
    p.add_argument("--print-path", action="store_true")

    p = add("run", cmd_run, "run a pinned tool directly with the given arguments")
    p.add_argument("tool", choices=TOOLS)
    p.add_argument("args", nargs=argparse.REMAINDER)

    p = add("lock", cmd_lock, "show the pinned versions")
    p.add_argument("--json", action="store_true")

    p = add("overlays", cmd_overlays, "list opengrep overlays and their rule packs")
    p.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args) or 0)
    except (ToolchainError, hooks.ScanError) as exc:
        print(f"[thyn-sec] error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
