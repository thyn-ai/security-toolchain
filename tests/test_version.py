"""Guard against the exact drift this repo shipped once already: __version__ bumped in one
place (or not bumped at all) while pyproject.toml's [project].version disagrees, silently
breaking verify.installed_tag() for every caller pinned to the new release. Read with the
standard library's tomllib (3.11+; the floor is 3.12), so the check sees the same value pip does.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from thyn_security_toolchain import __version__

REPO = Path(__file__).resolve().parents[1]


def test_dunder_version_matches_pyproject():
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert __version__ == project["version"], (
        f"thyn_security_toolchain.__version__ ({__version__!r}) != "
        f"pyproject.toml [project].version ({project['version']!r}) -- "
        "bump both in the same commit before tagging a release."
    )


def test_python_floor_is_the_org_standard():
    """3.12+ everywhere: the package, the composite action's default and the unit matrix."""
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["requires-python"] == ">=3.12"
    self_test = (REPO / ".github" / "workflows" / "self-test.yml").read_text(encoding="utf-8")
    assert 'python: ["3.12", "3.13"]' in self_test
    action = (REPO / "action.yml").read_text(encoding="utf-8")
    assert 'default: "3.12"' in action and "3.12+" in action
