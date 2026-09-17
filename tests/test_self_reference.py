"""Guard against the bug this repo actually shipped in v0.1.1 through v0.1.5: security-full.yml
and security-smoke.yml each install thyn-ai/security-toolchain via their own internal
`uses: thyn-ai/security-toolchain@vX.Y.Z` step, completely independent of whatever ref a
CALLER pins in its own `uses: .../security-full.yml@<sha>` line -- there is no way to make
`uses:` reference a dynamic value (confirmed with actionlint: "context 'inputs' is not allowed
here"), so this internal pin can only ever be a literal, and it must be bumped by hand on every
release. It sat at "v0.1.1" through five releases because nothing checked it. This test makes
that check itself the release gate: it fails loudly if a release ships with the internal pin
one version behind, which is exactly what happened for real.
"""

from __future__ import annotations

import re
from pathlib import Path

from thyn_security_toolchain import __version__

REPO = Path(__file__).resolve().parents[1]
_SELF_REF_RE = re.compile(r"uses:\s*thyn-ai/security-toolchain@(v[\d.]+)")


def _self_ref(workflow_name: str) -> str:
    text = (REPO / ".github" / "workflows" / workflow_name).read_text(encoding="utf-8")
    m = _SELF_REF_RE.search(text)
    assert m, f"{workflow_name} has no `uses: thyn-ai/security-toolchain@vX.Y.Z` self-reference"
    return m.group(1)


def test_security_full_self_reference_matches_this_release():
    ref = _self_ref("security-full.yml")
    assert ref == f"v{__version__}", (
        f"security-full.yml installs itself at {ref} but this release is v{__version__} -- "
        "every caller pinned to this release would silently run the wrong toolchain version "
        "in CI (local pre-commit hooks are unaffected; they install from a repo's own `rev:`)."
    )


def test_security_smoke_self_reference_matches_this_release():
    ref = _self_ref("security-smoke.yml")
    assert ref == f"v{__version__}", (
        f"security-smoke.yml installs itself at {ref} but this release is v{__version__}."
    )
