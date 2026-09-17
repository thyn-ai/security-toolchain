"""End-to-end proof, with the real pinned scanners: each fixture trips exactly its owner.

Needs network on first run (binaries, rules bundle, trivy checks, OSV API). Run with
``pytest -m integration``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from thyn_security_toolchain import changed
from thyn_security_toolchain.ci import run_ci
from thyn_security_toolchain.gate import (
    parse_gitleaks_json,
    parse_opengrep_sarif,
    parse_osv_json,
    parse_trivy_sarif,
    read_baseline,
)

pytestmark = pytest.mark.integration

OVERLAY = "pnpm-monorepo"


def _owners(out: Path, root: Path) -> dict:
    return {
        "gitleaks": {
            f.path.split("/")[0] for f in parse_gitleaks_json(out / "gitleaks.json", root)
        },
        "opengrep": {
            f.path.split("/")[0] for f in parse_opengrep_sarif(out / "opengrep.sarif", root)
        },
        "osv": {f.path.split("/")[0] for f in parse_osv_json(out / "osv.json", root)},
        "trivy": {f.path.split("/")[0] for f in parse_trivy_sarif(out / "trivy.sarif", root)},
    }


def test_each_fixture_trips_exactly_its_owner(
    fixture_repo: Path, tmp_path: Path, actions_env: Path
):
    out = tmp_path / "out"
    rc = run_ci(fixture_repo, OVERLAY, "ratchet", changed.ALL, out)
    assert rc == 1, (out / "summary.md").read_text()
    owners = _owners(out, fixture_repo)
    assert owners == {
        "gitleaks": {"gitleaks"},
        "opengrep": {"opengrep"},
        "osv": {"osv"},
        "trivy": {"trivy"},
    }, owners
    outputs = actions_env.read_text()
    assert "opengrep_sarif=" in outputs and "trivy_sarif=" in outputs and "exit_code=1" in outputs


def test_advisory_mode_never_fails(fixture_repo: Path, tmp_path: Path):
    assert run_ci(fixture_repo, OVERLAY, "advisory", changed.ALL, tmp_path / "out") == 0


def test_changed_file_scoping_skips_untouched_categories(fixture_repo: Path, tmp_path: Path):
    out = tmp_path / "out"
    rc = run_ci(fixture_repo, OVERLAY, "ratchet", ["clean/app.py"], out)
    assert rc == 1, "gitleaks always scans the whole tree, so the leaky fixture still fails"
    summary = (out / "summary.md").read_text()
    assert (
        "osv-scanner: no dependency manifest" in summary
        and "trivy config: no infrastructure" in summary
    )
    assert not (out / "osv.json").exists() and not (out / "trivy.sarif").exists()
    assert parse_opengrep_sarif(out / "opengrep.sarif", fixture_repo) == []


def test_measured_baseline_absorbs_debt_but_never_secrets(
    fixture_repo: Path, tmp_path: Path, actions_env: Path
):
    out = tmp_path / "out"
    assert run_ci(fixture_repo, OVERLAY, "ratchet", changed.ALL, out, measure_baseline=True) == 0
    for tool in ("opengrep", "osv", "trivy"):
        base = fixture_repo / "security" / "baseline" / f"{tool}.txt"
        assert base.is_file(), tool
        text = base.read_text()
        assert (
            "MEASURED ON CI" in text
            and "# run: https://github.com/thyn-ai/fixture/actions/runs/4242" in text
        )
        assert read_baseline(base), f"{tool} baseline should hold the fixture's findings"
    assert not (fixture_repo / "security" / "baseline" / "gitleaks.txt").exists()

    # With the baseline committed, only the secret still fails.
    rc = run_ci(fixture_repo, OVERLAY, "ratchet", changed.ALL, tmp_path / "out2")
    assert rc == 1
    (fixture_repo / "gitleaks" / "leaky.py").unlink()
    assert run_ci(fixture_repo, OVERLAY, "ratchet", changed.ALL, tmp_path / "out3") == 0

    # A brand-new finding fails the ratchet even though the old debt is baselined...
    new = fixture_repo / "opengrep" / "system_call.py"
    new.write_text("import os\nimport sys\n\nos.system('ls ' + sys.argv[1])\n")
    rc = run_ci(fixture_repo, OVERLAY, "ratchet", changed.ALL, tmp_path / "out4")
    assert rc == 1
    # ...and removing a baselined finding is reported as shrinkable.
    new.unlink()
    (fixture_repo / "trivy" / "main.tf").unlink()
    out5 = tmp_path / "out5"
    assert run_ci(fixture_repo, OVERLAY, "ratchet", changed.ALL, out5) == 0
    assert "fixed" in (out5 / "summary.md").read_text()


def test_clean_fixture_is_clean(fixture_repo: Path, tmp_path: Path):
    out = tmp_path / "out"
    assert run_ci(fixture_repo, OVERLAY, "ratchet", ["clean/app.py"], out, tools=("opengrep",)) == 0
    sarif = json.loads((out / "opengrep.sarif").read_text())
    assert sarif["runs"][0]["results"] == []
