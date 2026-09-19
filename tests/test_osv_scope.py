"""The overlay selects Opengrep rule packs and nothing else; osv-scanner never sees it.

thyn-ai/mojo-kernels#9 was reviewed as "`pnpm-monorepo` overlay on an npm repository: OSV finds
no lockfile, false-clean". run_ci hands hooks.osv the repository root and a report path only;
which lockfiles are read is osv-scanner's own recursive walk (proved against the real binary
in tests/test_integration.py). These tests pin that seam without the pinned binaries.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from thyn_security_toolchain import changed, hooks
from thyn_security_toolchain.ci import run_ci
from thyn_security_toolchain.cli import build_parser

NPM_LOCK = "typescript/fuse-mojo/package-lock.json"  # thyn-ai/mojo-kernels' real lockfile path


@pytest.fixture
def osv_calls(monkeypatch: pytest.MonkeyPatch) -> list:
    calls: list = []

    def stub(root: Path, report: Path):
        calls.append((root, report))
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps({"results": []}), encoding="utf-8")
        return []

    monkeypatch.setattr(hooks, "osv", stub)
    return calls


@pytest.mark.parametrize("overlay", ["python-javascript", "pnpm-monorepo", "python-uv", "site"])
def test_osv_gets_root_and_report_only_whatever_the_overlay(
    osv_calls: list, tmp_path: Path, overlay: str
):
    root = tmp_path / "repo"
    root.mkdir()
    out = tmp_path / "out"
    assert run_ci(root, overlay, "advisory", changed.ALL, out, tools=("osv",)) == 0
    assert osv_calls == [(root, out / "osv.json")]


def test_a_changed_npm_lockfile_puts_osv_in_scope_on_a_pull_request(
    osv_calls: list, tmp_path: Path
):
    root = tmp_path / "repo"
    root.mkdir()
    run_ci(root, "python-javascript", "advisory", [NPM_LOCK], tmp_path / "out", tools=("osv",))
    assert len(osv_calls) == 1


def test_no_manifest_change_skips_osv_with_a_note(osv_calls: list, tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    out = tmp_path / "out"
    run_ci(root, "python-javascript", "advisory", ["src/index.ts"], out, tools=("osv",))
    assert osv_calls == []
    summary = (out / "summary.md").read_text()
    assert "osv-scanner: no dependency manifest or lockfile changed; skipped" in summary


def test_hooks_osv_has_no_overlay_parameter():
    assert list(inspect.signature(hooks.osv).parameters) == ["root", "report"]


def test_only_the_opengrep_subcommands_take_an_overlay():
    parser = build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")
    with_overlay = {
        name
        for name, p in sub.choices.items()
        if any("--overlay" in a.option_strings for a in p._actions)
    }
    assert with_overlay == {"opengrep-changed", "opengrep-full", "ci"}, with_overlay
