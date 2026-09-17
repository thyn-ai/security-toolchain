"""Guard against the exact drift this repo shipped once already: __version__ bumped in one
place (or not bumped at all) while pyproject.toml's [project].version disagrees, silently
breaking verify.installed_tag() for every caller pinned to the new release. Regex, not
tomllib/tomli, to stay on the py3.9 matrix leg without adding a dependency.
"""

from __future__ import annotations

import re
from pathlib import Path

from thyn_security_toolchain import __version__

REPO = Path(__file__).resolve().parents[1]


def test_dunder_version_matches_pyproject():
    pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
    assert m, 'pyproject.toml has no top-level version = "..." line'
    assert __version__ == m.group(1), (
        f"thyn_security_toolchain.__version__ ({__version__!r}) != "
        f"pyproject.toml [project].version ({m.group(1)!r}) -- "
        "bump both in the same commit before tagging a release."
    )
