"""The authoritative gate: run every owner tool once, gate each against its baseline.

Used by the reusable ``security-full.yml`` workflow, by ``security-smoke.yml`` (gitleaks
only) and by the pre-push hooks (one tool at a time). The same code path everywhere is
the point: a laptop and a clean CI checkout must disagree only on *what changed*, never
on *how it is judged*.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from . import changed as changed_mod
from . import hooks
from .gate import (
    Finding,
    GateResult,
    annotate,
    drop_audit_results,
    evaluate,
    markdown_summary,
    read_baseline,
    write_baseline,
)
from .lock import tool_version
from .repo import baseline_path

TOOL_ORDER = ("gitleaks", "opengrep", "osv", "trivy")
LOCK_TOOL_NAME = {
    "opengrep": "opengrep",
    "osv": "osv-scanner",
    "trivy": "trivy",
    "gitleaks": "gitleaks",
}
CODE_SCANNING_SARIF = "opengrep.code-scanning.sarif"


def _gh_output(**pairs: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        for k, v in pairs.items():
            fh.write(f"{k}={v}\n")


def _gh_summary(markdown: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(markdown)


def code_scanning_sarif(report: Path, notes: list[str]) -> Path:
    """The Opengrep SARIF handed to code scanning: a copy of *report* minus its audit results.

    The gate has already parsed the full file, so the console summary and the reports artifact
    keep every finding; only GitHub's alert list stops filling with audit hints on intended
    subprocess / importlib / urllib use (see :func:`gate.drop_audit_results`).
    """
    upload = report.with_name(CODE_SCANNING_SARIF)
    shutil.copyfile(report, upload)
    dropped = drop_audit_results(upload)
    if dropped:
        notes.append(
            f"opengrep: {dropped} audit / low-confidence result(s) kept out of the code-scanning "
            "upload; they still count in the gate summary and stay in opengrep.sarif "
            "(opengrep_upload_audit: true uploads them as warnings)"
        )
    return upload


def test_path_note(scan_tests: bool, root: Path) -> str:
    """One summary line saying whether test code was in Opengrep's scope for this run."""
    if scan_tests:
        note = "opengrep: test paths scanned (opengrep_scan_tests: true)"
        if not (root / ".semgrepignore").is_file():
            note += (
                "; Opengrep's built-in .semgrepignore still skips tests/ and test/ (on full "
                "scans and, because --force-exclude applies it to named files too, on "
                "PR-scoped runs) -- commit a .semgrepignore (even an empty one) to lift that too"
            )
        return note
    return (
        f"opengrep: test paths out of scope by policy ({hooks.describe_test_paths()}); "
        "opengrep_scan_tests: true scans them"
    )


def gate_findings(tool: str, root: Path, findings: Sequence[Finding], mode: str) -> GateResult:
    if tool == "gitleaks":
        # Secrets are zero-tolerance: no baseline file, ever. Allowlisting happens in
        # .gitleaksignore (fingerprints) or .gitleaks.toml (paths), both reviewed in git.
        baseline: set[str] | None = set() if mode == "ratchet" else None
    else:
        baseline = read_baseline(baseline_path(root, tool))
    return evaluate(tool, findings, baseline, mode)


def run_ci(
    root: Path,
    overlay: str,
    mode: str,
    changed: changed_mod.Changed,
    out_dir: Path,
    tools: Sequence[str] = TOOL_ORDER,
    measure_baseline: bool = False,
    upload_audit: bool = False,
    scan_tests: bool = False,
) -> int:
    if mode not in ("advisory", "ratchet"):
        raise SystemExit(f"--mode must be advisory or ratchet, got {mode!r}")
    out_dir.mkdir(parents=True, exist_ok=True)
    if measure_baseline and not changed_mod.is_all(changed):
        print(
            "[thyn-sec] measure-baseline forces a full scan (a partial baseline would be a lie)",
            file=sys.stderr,
        )
        changed = changed_mod.ALL

    results: list[GateResult] = []
    all_findings: dict[str, list[Finding]] = {}
    notes: list[str] = []
    outputs: dict[str, str] = {}

    if "gitleaks" in tools:
        report = out_dir / "gitleaks.json"
        findings = hooks.gitleaks(root, "dir", report)
        all_findings["gitleaks"] = findings
        results.append(gate_findings("gitleaks", root, findings, mode))

    if "opengrep" in tools:
        targets = changed_mod.opengrep_targets(changed, root)
        if targets is not None and not targets:
            notes.append("opengrep: no scannable changed files in this diff; skipped")
        else:
            report = out_dir / "opengrep.sarif"
            findings = hooks.opengrep(root, overlay, targets, report, scan_tests=scan_tests)
            all_findings["opengrep"] = findings
            results.append(gate_findings("opengrep", root, findings, mode))
            notes.append(test_path_note(scan_tests, root))
            if report.is_file():
                upload = report if upload_audit else code_scanning_sarif(report, notes)
                outputs["opengrep_sarif"] = str(upload)

    if "osv" in tools:
        if changed_mod.any_match(changed, changed_mod.MANIFEST_RE):
            report = out_dir / "osv.json"
            findings = hooks.osv(root, report)
            all_findings["osv"] = findings
            results.append(gate_findings("osv", root, findings, mode))
        else:
            notes.append("osv-scanner: no dependency manifest or lockfile changed; skipped")

    if "trivy" in tools:
        if changed_mod.any_match(changed, changed_mod.IAC_RE):
            report = out_dir / "trivy.sarif"
            findings = hooks.trivy(root, report)
            all_findings["trivy"] = findings
            results.append(gate_findings("trivy", root, findings, mode))
            if report.is_file():
                outputs["trivy_sarif"] = str(report)
        else:
            notes.append("trivy config: no infrastructure definition changed; skipped")

    for res in results:
        annotate(res)
    for note in notes:
        print(f"[thyn-sec] {note}", file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
            print(f"::notice title=thyn-sec::{note}")

    exit_code = max((r.exit_code for r in results), default=0)

    if measure_baseline:
        written: list[str] = []
        for tool in ("opengrep", "osv", "trivy"):
            if tool not in all_findings:
                continue
            path = baseline_path(root, tool)
            write_baseline(
                path, tool, tool_version(LOCK_TOOL_NAME[tool]), [f.key for f in all_findings[tool]]
            )
            written.append(str(path.relative_to(root)))
        notes.append(
            "baseline measured: " + (", ".join(written) if written else "nothing to write")
        )
        outputs["baseline_files"] = " ".join(written)
        exit_code = 0

    summary = (
        f"### thyn-sec security gate\n\n"
        f"overlay `{overlay}` · mode `{mode}` · scope {changed_mod.describe(changed)}\n\n"
        + markdown_summary(results)
        + ("\n" + "\n".join(f"- {n}" for n in notes) + "\n" if notes else "")
    )
    (out_dir / "summary.md").write_text(summary, encoding="utf-8")
    _gh_summary(summary)
    outputs["exit_code"] = str(exit_code)
    outputs["summary"] = str(out_dir / "summary.md")
    _gh_output(**outputs)
    return exit_code
