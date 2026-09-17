from __future__ import annotations

import json
from pathlib import Path

from thyn_security_toolchain.gate import parse_opengrep_sarif


def _sarif_with_tags(rule_id: str, tags: list[str]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Opengrep OSS",
                        "rules": [
                            {
                                "id": rule_id,
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": tags},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": "error",
                        "message": {"text": "m"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "x.py"},
                                    "region": {"startLine": 1, "snippet": {"text": "run(cmd)"}},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_low_confidence_audit_rules_never_block(tmp_path: Path):
    """Semgrep-style `confidence: LOW` audit rules are advice, not gates."""
    p = tmp_path / "a.sarif"
    p.write_text(
        json.dumps(
            _sarif_with_tags(
                "dangerous-subprocess-use-audit", ["CWE-78", "LOW CONFIDENCE", "security"]
            )
        )
    )
    (f,) = parse_opengrep_sarif(p)
    assert f.severity == "MEDIUM" and not f.blocking


def test_medium_and_high_confidence_errors_block(tmp_path: Path):
    for conf in ("MEDIUM CONFIDENCE", "HIGH CONFIDENCE"):
        p = tmp_path / f"{conf[:1]}.sarif"
        p.write_text(json.dumps(_sarif_with_tags("subprocess-shell-true", ["CWE-78", conf])))
        (f,) = parse_opengrep_sarif(p)
        assert f.severity == "HIGH" and f.blocking, conf
