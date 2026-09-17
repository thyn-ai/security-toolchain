from __future__ import annotations

import subprocess
from collections.abc import Iterable
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "fixtures"


def materialize_fixtures(dest: Path, only: Iterable[str] | None = None) -> Path:
    """Copy fixtures into *dest* as a scratch git repo, making them 'live'."""
    keep = set(only) if only else None
    for src in sorted(FIXTURES.rglob("*.fixture")):
        rel = src.relative_to(FIXTURES)
        if keep is not None and rel.parts[0] not in keep:
            continue
        out = dest / rel.with_suffix("")
        if out.name == "dockerfile":
            # Stored lowercase so Trivy ignores the copy in this repo; live name must be Dockerfile.
            out = out.with_name("Dockerfile")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(src.read_text(encoding="utf-8").replace("__JOIN__", ""), encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=dest, check=True)
    subprocess.run(["git", "add", "-A"], cwd=dest, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-q",
            "-m",
            "fixtures",
        ],
        cwd=dest,
        check=True,
    )
    return dest


@pytest.fixture
def fixture_repo(tmp_path: Path) -> Path:
    return materialize_fixtures(tmp_path / "repo")


@pytest.fixture
def actions_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Pretend to be a GitHub Actions run so baselines may be written and outputs captured."""
    out = tmp_path / "gh_output.txt"
    summary = tmp_path / "gh_summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
    monkeypatch.setenv("GITHUB_REPOSITORY", "thyn-ai/fixture")
    monkeypatch.setenv("GITHUB_RUN_ID", "4242")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.delenv("GITHUB_EVENT_NAME", raising=False)
    monkeypatch.delenv("GITHUB_EVENT_PATH", raising=False)
    return out
