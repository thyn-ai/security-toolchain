from __future__ import annotations

import platform


class UnsupportedPlatform(RuntimeError):
    pass


def platform_key() -> str:
    """Return the lock-file asset key for the running machine, e.g. ``darwin-arm64``."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "linux-x86_64"
        if machine in ("aarch64", "arm64"):
            return "linux-aarch64"
    elif system == "darwin":
        if machine in ("arm64", "aarch64"):
            return "darwin-arm64"
        if machine in ("x86_64", "amd64"):
            return "darwin-x86_64"
    raise UnsupportedPlatform(
        f"thyn-sec supports linux/darwin on x86_64/arm64; this machine reports {system}/{machine}"
    )
