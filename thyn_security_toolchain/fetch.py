"""Download-once, verify-always fetcher for the pinned scanner binaries and rule bundle.

Cache layout (override root with ``THYN_SEC_CACHE_DIR``)::

    ~/.cache/thyn-sec/<tool>/<version>/<tool>          verified binary, mode 0755
    ~/.cache/thyn-sec/rules/<bundle>-<commit12>/       extracted rule tarball + .complete marker

``THYN_SEC_OFFLINE=1`` makes a cache miss a hard error instead of a download.
"""

from __future__ import annotations

import functools
import hashlib
import os
import shutil
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from .lock import asset_for, rules_spec

USER_AGENT = "thyn-security-toolchain (+https://github.com/thyn-ai/security-toolchain)"


class ToolchainError(RuntimeError):
    pass


def cache_dir() -> Path:
    env = os.environ.get("THYN_SEC_CACHE_DIR")
    if env:
        return Path(env).expanduser()
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "thyn-sec"


def offline() -> bool:
    return os.environ.get("THYN_SEC_OFFLINE", "").lower() not in ("", "0", "false", "no")


def _log(msg: str) -> None:
    if os.environ.get("THYN_SEC_QUIET", "").lower() in ("1", "true", "yes"):
        return
    print(f"[thyn-sec] {msg}", file=sys.stderr)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download_verified(url: str, dest: Path, expected_sha256: str, attempts: int = 3) -> None:
    """Stream *url* to *dest*, refusing to keep anything whose sha256 differs from the lock."""
    last: BaseException | None = None
    part = dest.with_name(dest.name + ".part")
    for attempt in range(1, attempts + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
            digest = hashlib.sha256()
            resp = urllib.request.urlopen(req, timeout=120)  # noqa: S310
            with resp, part.open("wb") as out:
                for chunk in iter(functools.partial(resp.read, 1 << 20), b""):
                    digest.update(chunk)
                    out.write(chunk)
            actual = digest.hexdigest()
            if actual != expected_sha256:
                part.unlink(missing_ok=True)
                raise ToolchainError(
                    f"sha256 mismatch for {url}\n"
                    f"  expected {expected_sha256}\n  actual   {actual}\n"
                    "Refusing to install: the lock is stale or the download was tampered with."
                )
            part.replace(dest)
            return
        except ToolchainError:
            raise
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = exc
            part.unlink(missing_ok=True)
            if attempt < attempts:
                time.sleep(2 * attempt)
    raise ToolchainError(f"download failed for {url} after {attempts} attempts: {last}")


def _extract_single_member(archive: Path, member_basename: str, dest: Path) -> None:
    with tarfile.open(archive, "r:gz") as tf:
        candidates = [
            m
            for m in tf.getmembers()
            if m.isfile()
            and Path(m.name).name == member_basename
            and ".." not in Path(m.name).parts
        ]
        if not candidates:
            raise ToolchainError(
                f"{archive.name} contains no regular file named {member_basename!r}"
            )
        src = tf.extractfile(candidates[0])
        if src is None:
            raise ToolchainError(f"could not read {member_basename!r} from {archive.name}")
        with src, dest.open("wb") as out:
            shutil.copyfileobj(src, out)


def tool_path(tool: str) -> Path:
    """Return the verified binary for *tool*, fetching it into the cache on first use."""
    version, asset = asset_for(tool)
    target = cache_dir() / tool / version / tool
    if target.is_file():
        return target
    if offline():
        raise ToolchainError(
            f"{tool} {version} is not cached at {target} and THYN_SEC_OFFLINE is set"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    _log(f"fetching {tool} {version} ({asset['url'].rsplit('/', 1)[-1]})")
    with tempfile.TemporaryDirectory(dir=str(target.parent)) as td:
        tmp = Path(td)
        downloaded = tmp / asset["url"].rsplit("/", 1)[-1]
        download_verified(asset["url"], downloaded, asset["sha256"])
        if asset.get("archive") == "tar.gz":
            binary = tmp / tool
            _extract_single_member(downloaded, asset["member"], binary)
        else:
            binary = downloaded
        binary.chmod(0o755)
        os.replace(str(binary), str(target))
    return target


def rules_path(bundle: str = "opengrep-rules") -> Path:
    """Return the extracted, pinned rules bundle directory (fetching on first use)."""
    spec = rules_spec(bundle)
    target = cache_dir() / "rules" / f"{bundle}-{spec['commit'][:12]}"
    marker = target / ".complete"
    if marker.is_file():
        return target
    if offline():
        raise ToolchainError(
            f"rules bundle {bundle} is not cached at {target} and THYN_SEC_OFFLINE is set"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    _log(f"fetching {bundle} @ {spec['commit'][:12]}")
    with tempfile.TemporaryDirectory(dir=str(target.parent)) as td:
        tmp = Path(td)
        tarball = tmp / "rules.tar.gz"
        download_verified(spec["url"], tarball, spec["sha256"])
        staging = tmp / "extract"
        staging.mkdir()
        _safe_extract_strip1(tarball, staging)
        if target.exists():
            shutil.rmtree(target)
        os.replace(str(staging), str(target))
        marker.write_text(spec["commit"] + "\n", encoding="utf-8")
    return target


def _safe_extract_strip1(tarball: Path, dest: Path) -> None:
    """Extract a GitHub archive tarball, dropping the top-level ``repo-<sha>/`` component."""
    with tarfile.open(tarball, "r:gz") as tf:
        for member in tf.getmembers():
            parts = Path(member.name).parts
            if len(parts) < 2 or ".." in parts or Path(member.name).is_absolute():
                continue
            if not (member.isfile() or member.isdir()):
                continue  # no symlinks/devices from a rules tarball
            rel = Path(*parts[1:])
            out = dest / rel
            if member.isdir():
                out.mkdir(parents=True, exist_ok=True)
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, out.open("wb") as fh:
                shutil.copyfileobj(src, fh)
