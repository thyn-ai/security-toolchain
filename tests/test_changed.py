from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from thyn_security_toolchain import changed


def _two_commit_repo(root: Path) -> tuple[Path, str, str]:
    """A real git repo with full history so ``git diff before...after`` genuinely succeeds."""
    repo = root / "repo"
    repo.mkdir()
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    (repo / "a.py").write_text("a = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run([*git, "commit", "-q", "-m", "one"], cwd=repo, check=True)
    before = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    (repo / "b.py").write_text("b = 2\n")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run([*git, "commit", "-q", "-m", "two"], cwd=repo, check=True)
    after = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()
    return repo, before, after


def _push_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict,
    *,
    ref: str | None = None,
    ref_name: str | None = None,
    ref_type: str | None = None,
) -> None:
    """Pretend to be a ``push`` run: payload on disk plus the ref-shaped env GitHub sets."""
    monkeypatch.delenv("THYN_SEC_CHANGED_FILES", raising=False)
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps(payload))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(ev))
    for key, value in (
        ("GITHUB_REF", ref),
        ("GITHUB_REF_NAME", ref_name),
        ("GITHUB_REF_TYPE", ref_type),
    ):
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)


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
    # A brand-new (non-default) branch: there is no base to diff against.
    _push_event(
        tmp_path,
        monkeypatch,
        {
            "ref": "refs/heads/feat/new",
            "before": changed.ZERO_SHA,
            "after": "abc",
            "repository": {"default_branch": "main"},
        },
        ref="refs/heads/feat/new",
        ref_name="feat/new",
    )
    assert changed.changed_files() == changed.ALL


def test_push_with_zero_before_and_unknown_default_is_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # Legacy payload shape (no repository block): the ZERO_SHA rule still applies.
    _push_event(tmp_path, monkeypatch, {"before": changed.ZERO_SHA, "after": "abc"})
    assert changed.changed_files() == changed.ALL


@pytest.mark.parametrize(
    "ref,ref_name",
    [
        ("refs/heads/main", "main"),  # both set, as on a real runner
        ("refs/heads/main", None),  # GITHUB_REF only
        (None, "main"),  # GITHUB_REF_NAME only (payload has no ref either)
    ],
    ids=["ref+ref_name", "ref-only", "ref_name-only"],
)
def test_push_to_default_branch_is_full_even_when_diff_would_succeed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    ref: str | None,
    ref_name: str | None,
):
    repo, before, after = _two_commit_repo(tmp_path)
    monkeypatch.chdir(repo)
    # Prove the premise: with full history the diff genuinely works and would yield a list.
    assert changed._git_diff(before, after) == ["b.py"]

    payload = {"before": before, "after": after, "repository": {"default_branch": "main"}}
    if ref is not None:
        payload["ref"] = ref
    _push_event(tmp_path, monkeypatch, payload, ref=ref, ref_name=ref_name)

    def _never(*_a, **_k):  # pragma: no cover - the assertion is the point
        raise AssertionError("git diff must not be consulted for a default-branch push")

    monkeypatch.setattr(changed, "_git_diff", _never)
    assert changed.changed_files() == changed.ALL
    err = capsys.readouterr().err
    assert "push to default branch 'main'" in err, err


def test_push_to_feature_branch_is_the_diff(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo, before, after = _two_commit_repo(tmp_path)
    monkeypatch.chdir(repo)
    _push_event(
        tmp_path,
        monkeypatch,
        {
            "ref": "refs/heads/feat/x",
            "before": before,
            "after": after,
            "repository": {"default_branch": "main"},
        },
        ref="refs/heads/feat/x",
        ref_name="feat/x",
    )
    assert changed.changed_files() == ["b.py"]


def test_push_of_tag_named_like_default_branch_is_not_the_default_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    # GITHUB_REF_NAME alone is ambiguous between a branch and a tag; the ref type decides.
    repo, before, after = _two_commit_repo(tmp_path)
    monkeypatch.chdir(repo)
    _push_event(
        tmp_path,
        monkeypatch,
        {
            "ref": "refs/tags/main",
            "before": before,
            "after": after,
            "repository": {"default_branch": "main"},
        },
        ref="refs/tags/main",
        ref_name="main",
        ref_type="tag",
    )
    assert changed.changed_files() == ["b.py"]
    # Same thing when only the short name is available.
    _push_event(
        tmp_path,
        monkeypatch,
        {"before": before, "after": after, "repository": {"default_branch": "main"}},
        ref_name="main",
        ref_type="tag",
    )
    assert changed.changed_files() == ["b.py"]


def test_push_without_default_branch_in_payload_keeps_diff_scoping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo, before, after = _two_commit_repo(tmp_path)
    monkeypatch.chdir(repo)
    _push_event(
        tmp_path,
        monkeypatch,
        {"ref": "refs/heads/main", "before": before, "after": after},
        ref="refs/heads/main",
        ref_name="main",
    )
    # Unknown default branch: we cannot prove this is the default, so the old rule stands
    # (diff, fail-closed to ALL). Callers on GitHub always get repository.default_branch.
    assert changed.changed_files() == ["b.py"]


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
        ("typescript/fuse-mojo/package-lock.json", True, False),  # thyn-ai/mojo-kernels (npm)
        ("yarn.lock", True, False),
        ("web/bun.lock", True, False),
        ("pixi.lock", True, False),
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


# ------------------------------------------------------------------------------- merge groups

QUEUE_REF = "refs/heads/gh-readonly-queue/main/pr-104-" + "9" * 40


def _merge_group_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: dict, *, authenticated: bool = False
) -> None:
    """Pretend to be a ``merge_group`` run: payload on disk, the queue ref, a token on request."""
    monkeypatch.delenv("THYN_SEC_CHANGED_FILES", raising=False)
    for key in ("GITHUB_TOKEN", "GH_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    if authenticated:
        monkeypatch.setenv("GITHUB_TOKEN", "t")
    ev = tmp_path / "event.json"
    ev.write_text(json.dumps(payload))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "merge_group")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(ev))
    monkeypatch.setenv("GITHUB_REPOSITORY", "thyn-ai/x")
    monkeypatch.setenv("GITHUB_REF", QUEUE_REF)
    monkeypatch.setenv("GITHUB_REF_NAME", QUEUE_REF[len("refs/heads/") :])


@pytest.mark.parametrize(
    "head_ref,number",
    [
        (QUEUE_REF, 104),
        ("refs/heads/gh-readonly-queue/release/1.x/pr-7-" + "a" * 40, 7),  # base with a slash
        ("refs/heads/gh-readonly-queue/main/pr-0-" + "a" * 40, None),
        ("refs/heads/gh-readonly-queue/main/pr-07-" + "a" * 40, None),
        ("refs/heads/gh-readonly-queue/main/pr-7-" + "a" * 39, None),  # not a full base sha
        ("refs/heads/gh-readonly-queue/main/pr-7-" + "a" * 40 + "/x", None),
        ("refs/heads/main", None),
        ("", None),
        (None, None),
        (7, None),
    ],
)
def test_merge_group_pull_number_is_read_off_the_queue_ref(head_ref, number):
    assert changed.merge_group_pull_number(head_ref) == number


def test_merge_group_is_scoped_like_the_pull_request_it_was_built_for(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    calls: list = []

    def api(repo: str, number: int, token: str, server: str):
        calls.append((repo, number, token, server))
        return ["b.py", "a.py", "a.py"]

    def never_diff(*_a, **_k):  # pragma: no cover - the assertion is the point
        raise AssertionError("the API answered; git diff must not be consulted")

    monkeypatch.setattr(changed, "_api_pr_files", api)
    monkeypatch.setattr(changed, "_git_diff", never_diff)
    _merge_group_event(
        tmp_path,
        monkeypatch,
        {
            "action": "checks_requested",
            "merge_group": {
                "head_sha": "1" * 40,
                "head_ref": QUEUE_REF,
                "base_sha": "0" * 40,
                "base_ref": "refs/heads/main",
            },
            "repository": {"default_branch": "main"},
        },
        authenticated=True,
    )
    assert changed.changed_files() == ["a.py", "b.py"]
    assert calls == [("thyn-ai/x", 104, "t", "https://github.com")]


def test_merge_group_without_a_token_diffs_base_sha_to_head_sha(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo, before, after = _two_commit_repo(tmp_path)
    monkeypatch.chdir(repo)

    def never_api(*_a, **_k):  # pragma: no cover - the assertion is the point
        raise AssertionError("the PR files API needs a token")

    monkeypatch.setattr(changed, "_api_pr_files", never_api)
    _merge_group_event(
        tmp_path,
        monkeypatch,
        {"merge_group": {"head_sha": after, "head_ref": QUEUE_REF, "base_sha": before}},
    )
    assert changed.changed_files() == ["b.py"]


def test_merge_group_falls_back_to_the_diff_when_the_api_cannot_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo, before, after = _two_commit_repo(tmp_path)
    monkeypatch.chdir(repo)
    monkeypatch.setattr(changed, "_api_pr_files", lambda *_a, **_k: None)
    _merge_group_event(
        tmp_path,
        monkeypatch,
        {"merge_group": {"head_sha": after, "head_ref": QUEUE_REF, "base_sha": before}},
        authenticated=True,
    )
    assert changed.changed_files() == ["b.py"]


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"merge_group": {}},
        {"merge_group": {"head_ref": QUEUE_REF}},  # a number but no token, and nothing to diff
        {"merge_group": {"head_ref": "refs/heads/x", "head_sha": "1" * 40, "base_sha": "0" * 40}},
    ],
    ids=["no-group", "empty-group", "number-only", "no-number-and-no-history"],
)
def test_merge_group_that_names_nothing_derivable_is_full(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: dict
):
    monkeypatch.chdir(tmp_path)  # not a git repo: the diff fallback must fail closed
    _merge_group_event(tmp_path, monkeypatch, payload)
    assert changed.changed_files() == changed.ALL
