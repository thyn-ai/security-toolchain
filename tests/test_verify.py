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
