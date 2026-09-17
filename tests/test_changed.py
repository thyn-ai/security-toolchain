from __future__ import annotations

import json
from pathlib import Path

import pytest

from thyn_security_toolchain import changed


def test_env_all_and_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("THYN_SEC_CHANGED_FILES", "ALL")
    assert changed.changed_files() == changed.ALL
    lst = tmp_path / "c.txt"
    lst.write_text("a.py\n\ninfra/main.tf\n")
    monkeypatch.setenv("THYN_SEC_CHANGED_FILES", str(lst))
    assert changed.changed_files() == ["a.py", "infra/main.tf"]
    monkeypatch.setenv("THYN_SEC_CHANGED_FILES", str(tmp_path / "nope.txt"))
    assert changed.changed_files() == changed.ALL, "a missing list must widen, never narrow"


def test_no_event_means_full_scan(monkeypatch: pytest.MonkeyPatch):
    for k in ("THYN_SEC_CHANGED_FILES", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH"):
        monkeypatch.delenv(k, raising=False)
    assert changed.changed_files() == changed.ALL


def test_push_with_zero_before_is_full(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("THYN_SEC_CHANGED_FILES", raising=False)
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps({"before": changed.ZERO_SHA, "after": "abc"}))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(ev))
    assert changed.changed_files() == changed.ALL


def test_pr_without_token_and_without_history_is_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("THYN_SEC_CHANGED_FILES", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    ev = tmp_path / "event.json"
    ev.write_text(
        json.dumps(
            {"pull_request": {"number": 7, "base": {"sha": "0" * 40}, "head": {"sha": "1" * 40}}}
        )
    )
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(ev))
    monkeypatch.setenv("GITHUB_REPOSITORY", "thyn-ai/x")
    monkeypatch.chdir(tmp_path)  # not a git repo: the diff fallback must fail closed
    assert changed.changed_files() == changed.ALL


@pytest.mark.parametrize(
    "path,manifest,iac",
    [
        ("pnpm-lock.yaml", True, False),
        ("python/uv.lock", True, False),
        ("apps/api-server/requirements.txt", True, False),
        ("pyproject.toml", True, False),
        ("infra/docker/Dockerfile.api.prod", False, True),
        ("infra/cloudflare/waf.tf", False, True),
        ("infra/azure/main.bicep", False, True),
        ("docker-compose.selfhosted.yml", False, True),
        ("charts/x/values.yaml", False, True),
        ("apps/worker/main.py", False, False),
        ("README.md", False, False),
    ],
)
def test_classification(path: str, manifest: bool, iac: bool):
    assert bool(changed.MANIFEST_RE.search(path)) is manifest, path
    assert bool(changed.IAC_RE.search(path)) is iac, path


def test_any_match_all_is_true():
    assert changed.any_match(changed.ALL, changed.IAC_RE)
    assert not changed.any_match(["a.py"], changed.IAC_RE)
    assert changed.any_match(["a.py", "infra/x.tf"], changed.IAC_RE)


def test_opengrep_targets_drops_missing_and_unsupported(tmp_path: Path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    got = changed.opengrep_targets(["a.py", "gone.py", "img.png", "Dockerfile"], tmp_path)
    assert got == ["a.py", "Dockerfile"]
    assert changed.opengrep_targets(changed.ALL, tmp_path) is None


def test_write_and_read_list_roundtrip(tmp_path: Path):
    p = tmp_path / "l.txt"
    changed.write_list(["b", "a"], p)
    assert changed.read_list(p) == ["b", "a"]
    changed.write_list(changed.ALL, p)
    assert changed.read_list(p) == changed.ALL
