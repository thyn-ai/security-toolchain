"""The authoritative gate: run every owner tool once, gate each against its baseline.

Used by the reusable ``security-full.yml`` workflow, by ``security-smoke.yml`` (gitleaks
only) and by the pre-push hooks (one tool at a time). The same code path everywhere is
the point: a laptop and a clean CI checkout must disagree only on *what changed*, never
on *how it is judged*.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import changed as changed_mod
from . import hooks
from .gate import (
    Finding,
    GateResult,
    annotate,
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
            findings = hooks.opengrep(root, overlay, targets, report)
            all_findings["opengrep"] = findings
            results.append(gate_findings("opengrep", root, findings, mode))
            if report.is_file():
                outputs["opengrep_sarif"] = str(report)

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
