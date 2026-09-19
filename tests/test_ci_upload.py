"""run_ci hands code scanning a copy of the Opengrep SARIF without audit results, while the
gate, the console summary and the reports artifact keep the full file. Opengrep itself is
replaced by a stub that writes a fixed SARIF, so this runs without the pinned binaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from thyn_security_toolchain import changed, hooks
from thyn_security_toolchain.ci import CODE_SCANNING_SARIF, run_ci
from thyn_security_toolchain.cli import build_parser
from thyn_security_toolchain.gate import demote_low_confidence_levels, parse_opengrep_sarif

AUDIT = "dangerous-subprocess-use-audit"
REAL = "subprocess-shell-true"


def _sarif() -> dict:
    def loc(uri: str, line: int) -> list:
        return [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
        ]

    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Opengrep OSS",
                        "rules": [
                            {
                                "id": AUDIT,
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": ["CWE-78", "LOW CONFIDENCE"]},
                            },
                            {
                                "id": REAL,
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": ["CWE-78", "MEDIUM CONFIDENCE"]},
                            },
                        ],
                    }
                },
                "results": [
                    {"ruleId": AUDIT, "message": {"text": "audit"}, "locations": loc("x.py", 8)},
                    {"ruleId": REAL, "message": {"text": "real"}, "locations": loc("x.py", 8)},
                ],
            }
        ],
    }


def _stub_opengrep(root: Path, overlay: str, targets, report: Path):
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(_sarif()), encoding="utf-8")
    demote_low_confidence_levels(report)  # exactly what the real hooks.opengrep does
    return parse_opengrep_sarif(report, root)


@pytest.fixture
def stubbed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(hooks, "opengrep", _stub_opengrep)
    root = tmp_path / "repo"
    root.mkdir()
    return root


def test_code_scanning_copy_drops_audit_results_but_gate_and_artifact_keep_them(
    stubbed: Path, tmp_path: Path, actions_env: Path
):
    out = tmp_path / "out"
    assert run_ci(stubbed, "python-uv", "advisory", changed.ALL, out, tools=("opengrep",)) == 0

    assert f"opengrep_sarif={out / CODE_SCANNING_SARIF}\n" in actions_env.read_text()
    full = json.loads((out / "opengrep.sarif").read_text())["runs"][0]["results"]
    upload = json.loads((out / CODE_SCANNING_SARIF).read_text())["runs"][0]["results"]
    assert [r["ruleId"] for r in full] == [AUDIT, REAL]
    assert [r["ruleId"] for r in upload] == [REAL]

    summary = (out / "summary.md").read_text()
    # The gate saw both: the real one is new+blocking, the audit one sits below the threshold.
    assert "| opengrep | advisory | 1 (1) | — | 0 | 1 |" in summary
    assert "1 audit / low-confidence result(s) kept out of the code-scanning upload" in summary
    assert "opengrep_upload_audit: true" in summary


def test_opt_in_uploads_the_full_demoted_sarif(stubbed: Path, tmp_path: Path, actions_env: Path):
    out = tmp_path / "out"
    run_ci(stubbed, "python-uv", "advisory", changed.ALL, out, ("opengrep",), upload_audit=True)
    assert f"opengrep_sarif={out / 'opengrep.sarif'}\n" in actions_env.read_text()
    assert not (out / CODE_SCANNING_SARIF).exists()
    run = json.loads((out / "opengrep.sarif").read_text())["runs"][0]
    assert [r["ruleId"] for r in run["results"]] == [AUDIT, REAL]
    levels = {r["id"]: r["defaultConfiguration"]["level"] for r in run["tool"]["driver"]["rules"]}
    assert levels == {AUDIT: "warning", REAL: "error"}  # v0.1.8 demotion still applies
    assert "code-scanning upload" not in (out / "summary.md").read_text()


def test_ci_flag_defaults_to_dropping_audit_results():
    parser = build_parser()
    assert parser.parse_args(["ci"]).opengrep_upload_audit is False
    assert parser.parse_args(["ci", "--opengrep-upload-audit"]).opengrep_upload_audit is True
