from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from ._platform import platform_key

DATA_DIR = Path(__file__).resolve().parent / "data"
LOCK_PATH = DATA_DIR / "toolchain.lock.json"

TOOLS = ("gitleaks", "opengrep", "osv-scanner", "trivy", "actionlint")
PLATFORMS = ("linux-x86_64", "linux-aarch64", "darwin-arm64", "darwin-x86_64")


class LockError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_lock() -> dict[str, Any]:
    with LOCK_PATH.open("r", encoding="utf-8") as fh:
        lock = json.load(fh)
    validate_lock(lock)
    return lock


def validate_lock(lock: dict[str, Any]) -> None:
    """Fail loudly on a malformed lock; this is the trust root for every binary we run."""
    if lock.get("schema") != 1:
        raise LockError(f"unsupported lock schema {lock.get('schema')!r}")
    tools = lock.get("tools") or {}
    for name in TOOLS:
        spec = tools.get(name)
        if not spec:
            raise LockError(f"lock is missing tool {name!r}")
        if not spec.get("version"):
            raise LockError(f"lock entry {name!r} has no version")
        assets = spec.get("assets") or {}
        for plat in PLATFORMS:
            asset = assets.get(plat)
            if not asset:
                raise LockError(f"lock entry {name!r} has no asset for {plat}")
            _validate_asset(name, plat, asset, spec["version"])
    rules = lock.get("rules") or {}
    for name, spec in rules.items():
        for key in ("commit", "url", "sha256"):
            if not spec.get(key):
                raise LockError(f"rules entry {name!r} is missing {key!r}")
        _validate_sha(f"rules {name}", spec["sha256"])


def _validate_asset(name: str, plat: str, asset: dict[str, Any], version: str) -> None:
    url = asset.get("url", "")
    if not url.startswith("https://github.com/"):
        raise LockError(f"{name}/{plat}: asset url must be a GitHub release https url, got {url!r}")
    if version not in url:
        raise LockError(f"{name}/{plat}: asset url {url!r} does not contain version {version!r}")
    _validate_sha(f"{name}/{plat}", asset.get("sha256", ""))
    archive = asset.get("archive")
    if archive not in (None, "tar.gz"):
        raise LockError(f"{name}/{plat}: unsupported archive type {archive!r}")
    if archive == "tar.gz" and not asset.get("member"):
        raise LockError(f"{name}/{plat}: tar.gz asset needs a 'member' to extract")


def _validate_sha(what: str, digest: str) -> None:
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise LockError(f"{what}: sha256 must be 64 lowercase hex chars, got {digest!r}")


def tool_version(tool: str) -> str:
    return str(load_lock()["tools"][tool]["version"])


def asset_for(tool: str, plat: str | None = None) -> tuple[str, dict[str, Any]]:
    """Return ``(version, asset)`` for *tool* on *plat* (default: this machine)."""
    lock = load_lock()
    spec = lock["tools"].get(tool)
    if spec is None:
        raise LockError(f"unknown tool {tool!r}; known: {', '.join(TOOLS)}")
    plat = plat or platform_key()
    try:
        return str(spec["version"]), spec["assets"][plat]
    except KeyError as exc:
        raise LockError(f"no {tool} asset for platform {plat}") from exc


def rules_spec(name: str = "opengrep-rules") -> dict[str, Any]:
    try:
        return load_lock()["rules"][name]
    except KeyError as exc:
        raise LockError(f"unknown rules bundle {name!r}") from exc
