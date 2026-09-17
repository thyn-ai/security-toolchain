from __future__ import annotations

import json
from pathlib import Path

import pytest

from thyn_security_toolchain import lock as lock_mod
from thyn_security_toolchain.lock import PLATFORMS, TOOLS, LockError, load_lock, validate_lock

REPO = Path(__file__).resolve().parents[1]


def test_lock_validates_and_covers_every_tool_and_platform():
    lock = load_lock()
    validate_lock(lock)
    assert set(lock["tools"]) == set(TOOLS)
    for name, spec in lock["tools"].items():
        assert set(spec["assets"]) == set(PLATFORMS), name
        for plat, asset in spec["assets"].items():
            assert asset["url"].startswith("https://github.com/"), (name, plat)
            assert spec["version"] in asset["url"], (name, plat)
            assert len(asset["sha256"]) == 64


def test_lock_digests_are_unique_per_asset():
    lock = load_lock()
    digests = [a["sha256"] for spec in lock["tools"].values() for a in spec["assets"].values()]
    digests += [r["sha256"] for r in lock["rules"].values()]
    assert len(digests) == len(set(digests)), "two assets sharing a digest means a copy-paste error"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda d: d.__setitem__("schema", 2),
        lambda d: d["tools"].pop("trivy"),
        lambda d: d["tools"]["gitleaks"]["assets"].pop("darwin-arm64"),
        lambda d: d["tools"]["gitleaks"]["assets"]["linux-x86_64"].__setitem__("sha256", "abc"),
        lambda d: d["tools"]["gitleaks"]["assets"]["linux-x86_64"].__setitem__(
            "url", "http://example.com/x"
        ),
        lambda d: d["tools"]["trivy"]["assets"]["linux-x86_64"].pop("member"),
    ],
)
def test_malformed_lock_is_rejected(mutation):
    data = json.loads(lock_mod.LOCK_PATH.read_text(encoding="utf-8"))
    mutation(data)
    with pytest.raises(LockError):
        validate_lock(data)


def test_security_dir_mirrors_package_data():
    """security/ is the human-facing view of the package data; the two must not drift."""
    pairs = {
        REPO / "security" / "toolchain.lock": lock_mod.LOCK_PATH,
        REPO / "security" / "gitleaks.toml": lock_mod.DATA_DIR / "gitleaks.toml",
        REPO / "security" / "opengrep" / "overlays.json": lock_mod.DATA_DIR
        / "opengrep-overlays.json",
    }
    for view, canonical in pairs.items():
        assert view.exists(), f"missing {view.relative_to(REPO)}"
        assert view.read_bytes() == canonical.read_bytes(), f"{view.relative_to(REPO)} drifted"
