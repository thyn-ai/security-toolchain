"""Malformed inputs fail with the documented error, never with a bare attribute error.

These are the concrete inputs the fuzz harnesses (fuzz/) found in their first minutes against
the previous code: a field of the wrong JSON type in the lock, the overlay file, a scanner
report or an event payload reached an attribute access. Each is kept here as a plain unit test
so the contract holds on every Python in the matrix without the fuzzing engine.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from thyn_security_toolchain import changed, hooks
from thyn_security_toolchain.gate import (
    PARSERS,
    ReportError,
    demote_low_confidence_levels,
    drop_audit_results,
)
from thyn_security_toolchain.lock import PLATFORMS, TOOLS, LockError, validate_lock


def _asset(url: str = "https://github.com/x/releases/download/1/x", sha: object = "a" * 64):
    return {"url": url, "sha256": sha}


def _tools(assets=None):
    assets = {p: _asset() for p in PLATFORMS} if assets is None else assets
    return {t: {"version": "1", "assets": assets} for t in TOOLS}


def _lock(**overrides):
    doc = {"schema": 1, "tools": _tools(), "rules": {}}
    doc.update(overrides)
    return doc


@pytest.mark.parametrize(
    "doc",
    [
        [1],
        {"schema": 1, "tools": [1]},
        {"schema": 1, "tools": {t: "x" for t in TOOLS}},
        {"schema": 1, "tools": {t: {"version": 1, "assets": {}} for t in TOOLS}},
        _lock(tools=_tools(assets=[1])),
        _lock(tools=_tools(assets={p: 5 for p in PLATFORMS})),
        _lock(tools=_tools(assets={p: _asset(url=7) for p in PLATFORMS})),
        _lock(tools=_tools(assets={p: _asset(sha=7) for p in PLATFORMS})),
        _lock(rules=[1]),
        _lock(rules={"r": "x"}),
        _lock(rules={"r": {"commit": 1, "url": "u", "sha256": "a" * 64}}),
    ],
    ids=[
        "lock-is-a-list",
        "tools-is-a-list",
        "tool-spec-is-a-string",
        "version-is-a-number",
        "assets-is-a-list",
        "asset-is-a-number",
        "url-is-a-number",
        "sha256-is-a-number",
        "rules-is-a-list",
        "rules-entry-is-a-string",
        "rules-commit-is-a-number",
    ],
)
def test_wrongly_typed_lock_fields_raise_lock_error(doc):
    with pytest.raises(LockError):
        validate_lock(doc)


def test_well_formed_minimal_lock_is_accepted():
    validate_lock(_lock())


@pytest.fixture
def overlays(monkeypatch: pytest.MonkeyPatch):
    def install(mapping: dict) -> None:
        monkeypatch.setattr(hooks, "load_overlays", lambda: mapping)

    return install


def test_unknown_parent_is_a_scan_error_not_a_key_error(overlays):
    overlays({"a": {"extends": ["nope"], "packs": ["p"]}})
    with pytest.raises(hooks.ScanError, match="extends unknown overlay 'nope'"):
        hooks.resolve_overlay("a")


@pytest.mark.parametrize(
    "spec",
    [
        "python",
        {"extends": "base"},
        {"packs": "python/lang/security"},
        {"exclude_rules": {"a": 1}},
        {"packs": ["ok", 3]},
    ],
    ids=["spec-string", "extends-string", "packs-string", "exclude-rules-object", "pack-int"],
)
def test_wrongly_typed_overlay_fields_raise_scan_error(overlays, spec):
    overlays({"a": spec, "base": {"packs": ["b"]}})
    with pytest.raises(hooks.ScanError):
        hooks.resolve_overlay("a")


def test_extends_cycle_terminates_with_parents_first(overlays):
    overlays({"a": {"extends": ["b"], "packs": ["pa"]}, "b": {"extends": ["a"], "packs": ["pb"]}})
    assert hooks.resolve_overlay("a") == (["pb", "pa"], [])
    assert hooks.resolve_overlay("b") == (["pa", "pb"], [])


@pytest.mark.parametrize("tool", sorted(PARSERS))
@pytest.mark.parametrize(
    "doc",
    [
        [1],
        "x",
        {"runs": [1], "results": [1]},
        {"runs": [{"results": [{"ruleId": 1, "message": "m", "locations": [1]}]}]},
        {"runs": [{"tool": {"driver": {"rules": [1]}}, "results": []}]},
        {"results": [{"packages": [1]}]},
        [{"File": 1}],
    ],
    ids=["list", "string", "runs-of-ints", "result-fields", "rules-of-ints", "packages", "File"],
)
def test_wrongly_shaped_reports_raise_report_error(tmp_path: Path, tool: str, doc):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    try:
        findings = PARSERS[tool](path, None)
    except ReportError as exc:
        assert tool in str(exc) and "report.json" in str(exc)
    else:
        # A shape this parser happens to tolerate must still yield well-formed findings.
        assert all(isinstance(f.key, str) and f.key for f in findings)


def test_report_error_is_a_value_error_like_bad_json(tmp_path: Path):
    path = tmp_path / "report.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        PARSERS["opengrep"](path, None)
    path.write_text("[" * 100000, encoding="utf-8")  # json.loads: RecursionError
    with pytest.raises(ReportError):
        PARSERS["osv"](path, None)
    path.write_text('{"runs": [1]}', encoding="utf-8")
    with pytest.raises(ValueError):
        PARSERS["opengrep"](path, None)
    assert issubclass(ReportError, ValueError)


@pytest.mark.parametrize("rewrite", [demote_low_confidence_levels, drop_audit_results])
def test_rewriters_refuse_a_malformed_sarif(tmp_path: Path, rewrite):
    path = tmp_path / "opengrep.sarif"
    path.write_text('{"runs": [{"tool": {"driver": {"rules": [1]}}, "results": [{}]}]}')
    with pytest.raises(ReportError):
        rewrite(path)


def test_event_payload_that_is_not_an_object_widens_to_all(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    ev = tmp_path / "event.json"
    ev.write_text("[1, 2]", encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(ev))
    monkeypatch.delenv("GITHUB_REF", raising=False)
    assert changed.from_github_event() == changed.ALL


@pytest.mark.parametrize(
    "event",
    [
        {"repository": "main"},
        {"repository": {"default_branch": 5}},
        {"repository": {"default_branch": "main"}, "ref": ["refs/heads/main"]},
        {"pull_request": [1]},
        {"pull_request": {"number": "7", "base": {"sha": 1}, "head": "x"}},
        {"before": 1, "after": None},
        {"merge_group": [1]},
        {"merge_group": {"head_ref": 5, "base_sha": 1, "head_sha": None}},
    ],
)
def test_wrongly_typed_event_fields_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, event
):
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps(event), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(ev))
    monkeypatch.delenv("GITHUB_REF", raising=False)
    monkeypatch.delenv("GITHUB_REF_NAME", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    for name in ("push", "pull_request", "merge_group"):
        monkeypatch.setenv("GITHUB_EVENT_NAME", name)
        assert changed.from_github_event() == changed.ALL
    assert changed._pushed_default_branch(event) in (None, "main")


def test_git_diff_refuses_revisions_that_are_not_commit_shas(monkeypatch: pytest.MonkeyPatch):
    calls = []
    monkeypatch.setattr(changed.subprocess, "run", lambda *a, **k: calls.append(a))
    assert changed._git_diff("-x", "b" * 40) is None
    assert changed._git_diff("HEAD~1", "HEAD") is None
    assert calls == [], "git must not be invoked with a revision that is not a full SHA"


def test_list_file_keeps_a_path_with_a_form_feed(tmp_path: Path):
    """str.splitlines would split 'a\\x0cb' in two; the list format is newline-separated."""
    p = tmp_path / "changed.txt"
    changed.write_list(["a\x0cb", "c d"], p)
    assert changed.read_list(p) == ["a\x0cb", "c d"]
