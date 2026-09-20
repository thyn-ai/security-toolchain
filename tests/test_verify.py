from __future__ import annotations

from pathlib import Path

from thyn_security_toolchain.verify import caller_pins, installed_tag, precommit_rev, verify_repo

REPO = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def _render_repo(
    root: Path, tag: str, sha: str = SHA, hook_types: str = "[pre-commit, pre-push]"
) -> None:
    block = (
        (REPO / "templates" / "pre-commit-block.yaml")
        .read_text()
        .format(rev=tag, overlay="python-uv")
    )
    (root / ".pre-commit-config.yaml").write_text(
        f"default_install_hook_types: {hook_types}\nrepos:\n{block}"
    )
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "security.yml").write_text(
        (REPO / "templates" / "security.yml")
        .read_text()
        .format(sha=sha, tag=tag, overlay="python-uv", mode="advisory")
    )


def test_parsers_extract_rev_and_pins(tmp_path: Path):
    _render_repo(tmp_path, "v9.9.9")
    assert precommit_rev((tmp_path / ".pre-commit-config.yaml").read_text()) == "v9.9.9"
    pins = caller_pins((tmp_path / ".github" / "workflows" / "security.yml").read_text())
    assert pins == [("security-full.yml", SHA, "v9.9.9")]


def test_consistent_repo_has_no_problems(tmp_path: Path):
    _render_repo(tmp_path, installed_tag())
    assert verify_repo(tmp_path) == []
    assert verify_repo(tmp_path, expect_ref=installed_tag()) == []
    assert verify_repo(tmp_path, expect_ref=SHA) == []


def test_mismatches_are_reported(tmp_path: Path):
    _render_repo(tmp_path, "v0.0.1")
    problems = verify_repo(tmp_path, expect_ref=installed_tag())
    assert any("rev v0.0.1" in p for p in problems)
    assert any("comment says v0.0.1" in p for p in problems)


def test_unpinned_uses_and_missing_pre_push_are_problems(tmp_path: Path):
    _render_repo(tmp_path, installed_tag(), sha="main", hook_types="[pre-commit]")
    problems = verify_repo(tmp_path)
    assert any("40-hex commit SHA" in p for p in problems)
    assert any("pre-push" in p for p in problems)


def test_repo_without_toolchain_is_fine(tmp_path: Path):
    (tmp_path / ".pre-commit-config.yaml").write_text("repos: []\n")
    assert verify_repo(tmp_path) == []


def _render_auto_merge_caller(root: Path, tag: str, sha: str = SHA) -> None:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "dependabot-auto-merge.yml").write_text(
        (REPO / "templates" / "dependabot-auto-merge.yml")
        .read_text()
        .format(sha=sha, tag=tag, auto_merge_majors="false")
    )


def test_auto_merge_caller_pin_is_verified_like_the_gate_pin(tmp_path: Path):
    _render_repo(tmp_path, installed_tag())
    _render_auto_merge_caller(tmp_path, installed_tag())
    assert verify_repo(tmp_path) == []
    assert verify_repo(tmp_path, expect_ref=SHA) == []
    # a stale auto-merge caller is a problem on its own, and so is a SHA the running gate is not
    _render_auto_merge_caller(tmp_path, "v0.0.1", sha="b" * 40)
    problems = verify_repo(tmp_path, expect_ref=SHA)
    where = ".github/workflows/dependabot-auto-merge.yml -> dependabot-auto-merge.yml"
    assert any(p.startswith(where) and "comment says v0.0.1" in p for p in problems), problems
    assert any(
        p.startswith(where) and f"SHA {'b' * 40} != checked-out toolchain" in p for p in problems
    )


def test_auto_merge_caller_alone_does_not_count_as_the_gate(tmp_path: Path):
    """The cross-checks between the hooks and CI are about the scanning gate."""
    # hooks installed, only the auto-merge caller in CI: nothing re-checks a clean checkout
    block = (
        (REPO / "templates" / "pre-commit-block.yaml")
        .read_text()
        .format(rev=installed_tag(), overlay="python-uv")
    )
    (tmp_path / ".pre-commit-config.yaml").write_text(
        f"default_install_hook_types: [pre-commit, pre-push]\nrepos:\n{block}"
    )
    _render_auto_merge_caller(tmp_path, installed_tag())
    problems = verify_repo(tmp_path)
    assert any("no workflow calls security-full/security-smoke" in p for p in problems), problems
    # the auto-merge caller with no hooks block is not "CI calls the toolchain but ..."
    other = tmp_path / "other"
    other.mkdir()
    (other / ".pre-commit-config.yaml").write_text("repos: []\n")
    _render_auto_merge_caller(other, installed_tag())
    assert verify_repo(other) == []
