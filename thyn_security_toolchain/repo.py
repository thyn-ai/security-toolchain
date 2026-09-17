"""Locate the target repository and its optional local overrides."""

from __future__ import annotations

import os
import subprocess
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

from .lock import DATA_DIR

# Directories no scanner should ever descend into. Repos may add more via their own
# .semgrepignore / trivy.yaml / osv-scanner.toml; these are the org-wide floor.
DEFAULT_SKIP_DIRS = (
    ".git",
    "node_modules",
    ".venv",
    "venv",
    ".pixi",
    "mojo_env",
    "mojo_build",
    "dist",
    "build",
    ".next",
    ".turbo",
    "vendor",
    ".cache",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
)


@lru_cache(maxsize=1)
def git_root(start: str | None = None) -> Path:
    cwd = start or os.getcwd()
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        return Path(out)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return Path(cwd).resolve()


def in_github_actions() -> bool:
    return os.environ.get("GITHUB_ACTIONS", "").lower() == "true"


def gitleaks_config(root: Path) -> Path:
    local = root / ".gitleaks.toml"
    return local if local.is_file() else DATA_DIR / "gitleaks.toml"


def local_opengrep_rules(root: Path) -> list[Path]:
    rules_dir = root / "security" / "opengrep"
    if not rules_dir.is_dir():
        return []
    return sorted(p for p in rules_dir.iterdir() if p.suffix in (".yml", ".yaml") and p.is_file())


def baseline_path(root: Path, tool: str) -> Path:
    return root / "security" / "baseline" / f"{tool}.txt"


def existing_files(root: Path, paths: Iterable[str]) -> list[str]:
    """Keep only paths that still exist as regular files (pre-commit hands us deletions too)."""
    kept: list[str] = []
    for p in paths:
        if (root / p).is_file():
            kept.append(p)
    return kept
