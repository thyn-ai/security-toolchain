"""Test code is out of Opengrep's scope by default -- the scanner never produces the result, so
neither the gate nor the code-scanning upload can see it -- and one flag per caller turns the
policy off. Opengrep itself is replaced by a recorder here; the real-binary proof, with a
finding copied under every test-path shape, is
test_integration.py::test_test_paths_are_out_of_scope_unless_opted_in.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from thyn_security_toolchain import changed, hooks
from thyn_security_toolchain.ci import run_ci
from thyn_security_toolchain.cli import build_parser, main
from thyn_security_toolchain.repo import DEFAULT_SKIP_DIRS

# The policy as documented in the README and the security-full.yml input, spelled out so a
# change to the list has to be made in both places on purpose.
DOCUMENTED = (
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

EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "Opengrep OSS", "rules": []}}, "results": []}],
}


def _excludes(cmd: list[str]) -> list[str]:
    return [cmd[i + 1] for i, arg in enumerate(cmd) if arg == "--exclude"]


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[list[str]]:
    """Drive hooks.opengrep for real up to the subprocess, which is replaced by a recorder
    that writes an empty SARIF where the real scanner would."""
    calls: list[list[str]] = []

    def fake_run(cmd, cwd, ok=(0,), env=None):
        argv = [str(c) for c in cmd]
        calls.append(argv)
        Path(argv[argv.index("--sarif-output") + 1]).write_text(json.dumps(EMPTY_SARIF))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(hooks, "_run", fake_run)
    monkeypatch.setattr(hooks, "tool_path", lambda tool: tmp_path / "bin" / tool)
    monkeypatch.setattr(
        hooks, "opengrep_configs", lambda root, overlay: ([tmp_path / "rules" / "python"], [])
    )
    return calls


def test_the_glob_list_is_the_documented_policy():
    assert hooks.OPENGREP_TEST_PATH_GLOBS == DOCUMENTED
    assert hooks.opengrep_excludes() == [*DEFAULT_SKIP_DIRS, *DOCUMENTED]
    assert hooks.opengrep_excludes(scan_tests=True) == list(DEFAULT_SKIP_DIRS)
    # The summary line is derived from the globs, never a second hand-written copy.
    assert hooks.describe_test_paths().split(", ") == [g[3:] for g in DOCUMENTED]
    assert "benchmarks" not in hooks.describe_test_paths()


def test_scanner_gets_every_test_glob_and_force_exclude(recorded: list, tmp_path: Path):
    hooks.opengrep(tmp_path, "python-uv", ["tests/test_x.py", "app.py"], tmp_path / "r.sarif")
    (cmd,) = recorded
    excludes = _excludes(cmd)
    for glob in DOCUMENTED:
        assert glob in excludes, glob
    for skip in DEFAULT_SKIP_DIRS:
        assert skip in excludes, skip
    # Without it Opengrep applies --exclude only to files it discovers itself, so a test file
    # named by pre-commit or by a PR-scoped run would be scanned anyway.
    assert "--force-exclude" in cmd
    assert cmd[-2:] == ["tests/test_x.py", "app.py"], "explicit targets are still handed over"


def test_opt_out_drops_exactly_the_test_globs(recorded: list, tmp_path: Path):
    hooks.opengrep(tmp_path, "python-uv", None, tmp_path / "r.sarif", scan_tests=True)
    (cmd,) = recorded
    excludes = _excludes(cmd)
    assert not set(excludes) & set(DOCUMENTED)
    assert excludes == list(DEFAULT_SKIP_DIRS), "the org-wide skip dirs are not negotiable"
    assert "--force-exclude" in cmd and cmd[-1] == "."


def test_cli_flags_default_to_the_policy():
    parser = build_parser()
    assert parser.parse_args(["ci"]).opengrep_scan_tests is False
    assert parser.parse_args(["ci", "--opengrep-scan-tests"]).opengrep_scan_tests is True
    for sub in ("opengrep-changed", "opengrep-full"):
        assert parser.parse_args([sub]).scan_tests is False, sub
        assert parser.parse_args([sub, "--scan-tests"]).scan_tests is True, sub


def test_hook_commands_forward_the_flag(recorded: list, tmp_path: Path):
    (tmp_path / "app.py").write_text("x = 1\n")
    root = ["--root", str(tmp_path)]
    assert main(["opengrep-changed", *root, "app.py"]) == 0
    assert main(["opengrep-changed", *root, "--scan-tests", "app.py"]) == 0
    assert main(["opengrep-full", *root]) == 0
    assert main(["opengrep-full", *root, "--scan-tests"]) == 0
    policy = [bool(set(_excludes(cmd)) & set(DOCUMENTED)) for cmd in recorded]
    assert policy == [True, False, True, False]


def test_run_ci_forwards_the_flag_and_the_summary_says_so(
    recorded: list, tmp_path: Path, actions_env: Path
):
    root = tmp_path / "repo"
    root.mkdir()
    out = tmp_path / "out"
    assert run_ci(root, "python-uv", "advisory", changed.ALL, out, tools=("opengrep",)) == 0
    assert set(_excludes(recorded[-1])) >= set(DOCUMENTED)
    summary = (out / "summary.md").read_text()
    assert "opengrep: test paths out of scope by policy (tests/**, test/**" in summary
    assert "opengrep_scan_tests: true scans them" in summary
    assert "test paths scanned" not in summary

    out2 = tmp_path / "out2"
    run_ci(root, "python-uv", "advisory", changed.ALL, out2, ("opengrep",), scan_tests=True)
    assert not set(_excludes(recorded[-1])) & set(DOCUMENTED)
    summary2 = (out2 / "summary.md").read_text()
    assert "opengrep: test paths scanned (opengrep_scan_tests: true)" in summary2
    assert "out of scope by policy" not in summary2
    # No .semgrepignore in the repo: the scanner's own default still skips tests/ and test/,
    # and the summary has to say so rather than let the flag look fully effective.
    assert "built-in .semgrepignore still skips tests/ and test/" in summary2

    (root / ".semgrepignore").write_text("")
    out3 = tmp_path / "out3"
    run_ci(root, "python-uv", "advisory", changed.ALL, out3, ("opengrep",), scan_tests=True)
    summary3 = (out3 / "summary.md").read_text()
    assert "opengrep: test paths scanned (opengrep_scan_tests: true)" in summary3
    assert "built-in .semgrepignore" not in summary3


def test_ci_command_forwards_the_flag(recorded: list, tmp_path: Path, actions_env: Path):
    root = tmp_path / "repo"
    root.mkdir()
    base = ["ci", "--root", str(root), "--tools", "opengrep", "--changed", "ALL"]
    assert main([*base, "--out-dir", str(tmp_path / "a")]) == 0
    assert main([*base, "--out-dir", str(tmp_path / "b"), "--opengrep-scan-tests"]) == 0
    policy = [bool(set(_excludes(cmd)) & set(DOCUMENTED)) for cmd in recorded]
    assert policy == [True, False]


def test_workflow_input_and_readme_document_the_same_policy():
    repo = Path(__file__).resolve().parents[1]
    workflow = (repo / ".github" / "workflows" / "security-full.yml").read_text(encoding="utf-8")
    readme = (repo / "README.md").read_text(encoding="utf-8")
    assert "opengrep_scan_tests:" in workflow and "--opengrep-scan-tests" in workflow
    assert "opengrep_scan_tests: true" in readme and "--opengrep-scan-tests" in readme
    for glob in DOCUMENTED:
        if glob.endswith("/**"):
            assert glob in workflow and f"`{glob}`" in readme, glob
        else:
            bare = glob[len("**/") :]
            # per-extension globs are written once as *.test.ts|tsx|js in prose
            stem = bare.rsplit(".", 1)[0] if bare.startswith("*.") else bare
            assert stem in workflow and stem in readme, glob
