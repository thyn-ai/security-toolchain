from __future__ import annotations

import json
from pathlib import Path

import pytest

from thyn_security_toolchain.gate import (
    HEADER_MARKER,
    Finding,
    evaluate,
    normalize_opengrep_rule_id,
    parse_gitleaks_json,
    parse_opengrep_sarif,
    parse_osv_json,
    parse_trivy_sarif,
    read_baseline,
    render_baseline,
    write_baseline,
)


def _sarif(results, rules=None, tool="Opengrep OSS"):
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool, "rules": rules or []}}, "results": results}],
    }


def _loc(uri, line, snippet=None):
    region = {"startLine": line}
    if snippet is not None:
        region["snippet"] = {"text": snippet}
    return [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}]


def test_opengrep_key_is_line_independent(tmp_path: Path):
    a = _sarif(
        [
            {
                "ruleId": "subprocess-shell-true",
                "level": "error",
                "message": {"text": "m"},
                "locations": _loc("app/x.py", 3, "  subprocess.call(cmd,   shell=True)"),
            }
        ]
    )
    b = _sarif(
        [
            {
                "ruleId": "subprocess-shell-true",
                "level": "error",
                "message": {"text": "m"},
                "locations": _loc("app/x.py", 42, "subprocess.call(cmd, shell=True)  "),
            }
        ]
    )
    pa, pb = tmp_path / "a.sarif", tmp_path / "b.sarif"
    pa.write_text(json.dumps(a))
    pb.write_text(json.dumps(b))
    fa, fb = parse_opengrep_sarif(pa), parse_opengrep_sarif(pb)
    assert (
        fa[0].key
        == fb[0].key
        == "subprocess-shell-true :: app/x.py :: subprocess.call(cmd, shell=True)"
    )
    assert fa[0].severity == "HIGH" and fa[0].blocking


def test_opengrep_rule_id_prefix_is_stripped():
    raw = (
        "home.runner..cache.thyn-sec.rules.opengrep-rules-f1d2b562b414."
        "python.lang.security.audit.subprocess-shell-true"
    )
    assert normalize_opengrep_rule_id(raw) == "python.lang.security.audit.subprocess-shell-true"
    assert normalize_opengrep_rule_id("subprocess-shell-true") == "subprocess-shell-true"


def test_trivy_severity_from_security_severity_and_dedup(tmp_path: Path):
    rules = [
        {
            "id": "DS-0002",
            "shortDescription": {"text": "root user"},
            "properties": {"security-severity": "8.0"},
        },
        {
            "id": "AWS-0086",
            "shortDescription": {"text": "public acl"},
            "properties": {"security-severity": "9.5"},
        },
    ]
    res = [
        {
            "ruleId": "DS-0002",
            "level": "error",
            "message": {"text": "x"},
            "locations": _loc("infra/Dockerfile", 1),
        },
        {
            "ruleId": "DS-0002",
            "level": "error",
            "message": {"text": "x"},
            "locations": _loc("infra/Dockerfile", 7),
        },
        {
            "ruleId": "AWS-0086",
            "level": "error",
            "message": {"text": "y"},
            "locations": _loc("infra/main.tf", 3),
        },
    ]
    p = tmp_path / "t.sarif"
    p.write_text(json.dumps(_sarif(res, rules, tool="Trivy")))
    findings = parse_trivy_sarif(p)
    assert [f.key for f in findings] == ["DS-0002 :: infra/Dockerfile", "AWS-0086 :: infra/main.tf"]
    assert [f.severity for f in findings] == ["HIGH", "CRITICAL"]


def test_osv_key_prefers_ghsa_and_scores_severity(tmp_path: Path):
    data = {
        "results": [
            {
                "source": {"path": "osv/requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "PYSEC-2018-28",
                                "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
                                "summary": "creds leak",
                            }
                        ],
                        "groups": [{"ids": ["PYSEC-2018-28"], "max_severity": "7.5"}],
                    },
                    {
                        "package": {"name": "urllib3", "version": "1.24.1", "ecosystem": "PyPI"},
                        "vulnerabilities": [{"id": "PYSEC-2019-132", "aliases": []}],
                        "groups": [{"ids": ["PYSEC-2019-132"], "max_severity": ""}],
                    },
                ],
            }
        ]
    }
    p = tmp_path / "osv.json"
    p.write_text(json.dumps(data))
    f = parse_osv_json(p)
    assert f[0].key == "PyPI/requests@2.19.0 :: GHSA-x84v-xcm2-53pg" and f[0].severity == "HIGH"
    assert (
        f[1].key == "PyPI/urllib3@1.24.1 :: PYSEC-2019-132"
        and f[1].severity == "MEDIUM"
        and not f[1].blocking
    )


def test_gitleaks_uses_native_fingerprint(tmp_path: Path):
    p = tmp_path / "gl.json"
    p.write_text(
        json.dumps(
            [
                {
                    "RuleID": "aws-access-token",
                    "File": "a.py",
                    "StartLine": 3,
                    "Fingerprint": "a.py:aws-access-token:3",
                    "Description": "AWS",
                    "Secret": "REDACTED",
                }
            ]
        )
    )
    f = parse_gitleaks_json(p)
    assert f[0].key == "a.py:aws-access-token:3" and f[0].severity == "CRITICAL"
    assert "REDACTED" not in f[0].message or "redacted" in f[0].message.lower()
    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert parse_gitleaks_json(empty) == []


def _f(key, sev="HIGH"):
    return Finding("opengrep", key, sev, "p", 1, "m", "r")


def test_evaluate_advisory_without_baseline_never_fails():
    r = evaluate("opengrep", [_f("a"), _f("b", "LOW")], None, "advisory")
    assert r.exit_code == 0 and not r.baseline_present and len(r.new) == 1 and r.ignored_low == 1


def test_evaluate_ratchet_without_baseline_is_still_advisory():
    r = evaluate("opengrep", [_f("a")], None, "ratchet")
    assert r.exit_code == 0 and "advisory" in r.summary


def test_evaluate_ratchet_with_baseline_fails_only_on_new_blocking():
    base = {"known"}
    ok = evaluate("opengrep", [_f("known"), _f("newlow", "LOW")], base, "ratchet")
    assert ok.exit_code == 0 and len(ok.known) == 1 and ok.ignored_low == 1
    bad = evaluate("opengrep", [_f("known"), _f("brand-new")], base, "ratchet")
    assert bad.exit_code == 1 and [f.key for f in bad.new] == ["brand-new"]
    shrink = evaluate("opengrep", [], base, "ratchet")
    assert shrink.exit_code == 0 and shrink.fixed == ["known"]


def test_gitleaks_zero_tolerance_via_empty_baseline():
    r = evaluate(
        "gitleaks",
        [Finding("gitleaks", "a.py:aws:1", "CRITICAL", "a.py", 1, "m", "aws")],
        set(),
        "ratchet",
    )
    assert r.exit_code == 1


def test_baseline_roundtrip_and_header(tmp_path: Path):
    text = render_baseline(
        "opengrep", "1.30.0", ["b :: y", "a :: x", "a :: x"], "deadbeef", "https://run"
    )
    assert HEADER_MARKER in text and "may only shrink" in text
    p = tmp_path / "opengrep.txt"
    p.write_text(text)
    assert read_baseline(p) == {"a :: x", "b :: y"}
    assert read_baseline(tmp_path / "missing.txt") is None


def test_write_baseline_refuses_outside_ci(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    with pytest.raises(RuntimeError):
        write_baseline(tmp_path / "x.txt", "opengrep", "1.30.0", ["k"])


def test_write_baseline_records_commit_and_run(tmp_path: Path, actions_env):
    p = tmp_path / "security" / "baseline" / "trivy.txt"
    write_baseline(p, "trivy", "0.74.0", ["DS-0002 :: Dockerfile"])
    text = p.read_text()
    assert "# commit: 0123456789abcdef0123456789abcdef01234567" in text
    assert "# run: https://github.com/thyn-ai/fixture/actions/runs/4242" in text
