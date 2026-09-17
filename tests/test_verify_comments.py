from __future__ import annotations

from pathlib import Path

from thyn_security_toolchain.verify import caller_pins, verify_repo

REPO = Path(__file__).resolve().parents[1]


def test_commented_uses_lines_are_documentation_not_calls():
    text = (
        "# Call it like this:\n"
        "#   uses: thyn-ai/security-toolchain/.github/workflows/security-full.yml@<sha> # vX.Y.Z\n"
        "jobs:\n"
        "  full:\n"
        "    uses: thyn-ai/security-toolchain/.github/workflows/security-full.yml@"
        + "b" * 40
        + " # v0.1.0\n"
    )
    assert caller_pins(text) == [("security-full.yml", "b" * 40, "v0.1.0")]


def test_the_toolchain_repo_itself_verifies_clean():
    """Our own workflows document the call in comments; that must not count as a caller."""
    assert verify_repo(REPO) == []
