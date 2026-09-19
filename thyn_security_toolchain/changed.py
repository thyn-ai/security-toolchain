"""Changed-file derivation for PR-scoped scanning (fail-closed to a full scan).

Mirrors the engine's blast-radius selector in ``.github/workflows/ci.yml``: on a
``pull_request`` event the authoritative list is ``GET /pulls/{n}/files`` (needs no
local history); on ``push`` to a non-default branch it is ``git diff before...after``;
anything that cannot be derived with certainty returns ``ALL`` so the scan widens rather
than narrows.

A push to the repository's default branch is always ``ALL``, by policy rather than by
accident. GitHub marks every code-scanning alert that is absent from the newest SARIF
upload for a ref+category as fixed, so a partial upload for ``refs/heads/<default>`` would
close alerts in untouched files and reopen them on the next full run. Until this rule
existed the promise only held because a shallow ``actions/checkout`` made the diff fail
and fall back to ``ALL``.

Callers that already know the diff (the engine's ``id: impact`` step) can hand it over
verbatim through ``THYN_SEC_CHANGED_FILES`` (a path to a newline-separated file, or
the literal ``ALL``).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path
from typing import Union

ALL = "ALL"
Changed = Union[str, list[str]]  # ALL or a concrete list

ZERO_SHA = "0" * 40

# Files whose change means "dependencies may have changed" -> run OSV.
MANIFEST_RE = re.compile(
    r"(^|/)("
    r"requirements[^/]*\.txt|pyproject\.toml|setup\.py|setup\.cfg|uv\.lock|poetry\.lock|Pipfile(\.lock)?|"
    r"package\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock(b)?|"
    r"go\.mod|go\.sum|Cargo\.(toml|lock)|Gemfile(\.lock)?|composer\.(json|lock)|"
    r"pixi\.(toml|lock)|osv-scanner\.toml"
    r")$"
)

# Files whose change means "infrastructure definitions may have changed" -> run Trivy config.
IAC_RE = re.compile(
    r"(^|/)("
    r"Dockerfile[^/]*|[^/]*\.dockerfile|(docker-)?compose[^/]*\.ya?ml|"
    r"[^/]*\.tf|[^/]*\.tfvars|[^/]*\.bicep|[^/]*\.bicepparam|"
    r"Chart\.ya?ml|values[^/]*\.ya?ml|kustomization\.ya?ml|trivy\.yaml|\.trivyignore"
    r")$"
    r"|^(infra|infrastructure|deploy|deployment|charts?|helm|k8s|kubernetes|manifests|terraform)/"
)

# Extensions opengrep can parse; other changed files are skipped in changed-file mode.
OPENGREP_EXT = (
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".vue",
    ".yml",
    ".yaml",
    ".json",
    ".tf",
    ".hcl",
    ".bicep",
    ".sh",
    ".bash",
    ".html",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".rb",
    ".php",
    ".cs",
    ".swift",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".sol",
    ".toml",
)


def _log(msg: str) -> None:
    print(f"[thyn-sec changed-files] {msg}", file=sys.stderr)


def from_env() -> Changed | None:
    spec = os.environ.get("THYN_SEC_CHANGED_FILES")
    if not spec:
        return None
    if spec.strip().upper() == ALL:
        return ALL
    p = Path(spec)
    if not p.is_file():
        _log(f"THYN_SEC_CHANGED_FILES={spec!r} is not a file; widening to ALL")
        return ALL
    files = [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return files


def _api_pr_files(repo: str, number: int, token: str, server: str) -> list[str] | None:
    api = os.environ.get("GITHUB_API_URL") or (
        "https://api.github.com"
        if server.rstrip("/") == "https://github.com"
        else server.rstrip("/") + "/api/v3"
    )
    files: list[str] = []
    page = 1
    while True:
        url = f"{api}/repos/{repo}/pulls/{number}/files?per_page=100&page={page}"
        req = urllib.request.Request(  # noqa: S310
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "thyn-security-toolchain",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                batch = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            _log(f"PR files API failed on page {page}: {exc}")
            return None
        if not isinstance(batch, list):
            return None
        for item in batch:
            name = item.get("filename")
            if name:
                files.append(name)
            prev = item.get("previous_filename")
            if prev:
                files.append(prev)
        if len(batch) < 100:
            break
        page += 1
        if page > 30:  # 3000 files: this is not a "changed files" PR any more
            _log("PR touches >3000 files; widening to ALL")
            return None
    return files


def _git_diff(base: str, head: str, cwd: str | None = None) -> list[str] | None:
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", f"{base}...{head}"],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        _log(f"git diff {base}...{head} failed: {getattr(exc, 'stderr', exc)}")
        return None
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def _pushed_default_branch(event: dict) -> str | None:
    """Name of the default branch when the pushed ref *is* that branch, else None.

    The default branch comes from the event payload (``repository.default_branch``); the
    pushed ref from ``GITHUB_REF`` (falling back to the payload's ``ref``) or, when only
    the short name is available, from ``GITHUB_REF_NAME``. A tag that happens to share
    the default branch's name (``GITHUB_REF_TYPE=tag``) does not count.
    """
    default = ((event.get("repository") or {}).get("default_branch") or "").strip()
    if not default:
        return None
    ref = os.environ.get("GITHUB_REF") or event.get("ref") or ""
    if ref == f"refs/heads/{default}":
        return default
    if ref:
        return None  # a fully qualified ref that is not the default branch
    ref_name = os.environ.get("GITHUB_REF_NAME", "")
    if ref_name == default and os.environ.get("GITHUB_REF_TYPE", "branch") != "tag":
        return default
    return None


def from_github_event() -> Changed | None:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not event_name or not event_path or not Path(event_path).is_file():
        return None
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except ValueError:
        return ALL
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    if event_name in ("pull_request", "pull_request_target"):
        number = (event.get("pull_request") or {}).get("number") or event.get("number")
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if number and token and repo:
            files = _api_pr_files(repo, int(number), token, server)
            if files is not None:
                return sorted(set(files))
        base = (event.get("pull_request") or {}).get("base", {}).get("sha")
        head = (event.get("pull_request") or {}).get("head", {}).get("sha")
        if base and head:
            files = _git_diff(base, head)
            if files is not None:
                return sorted(set(files))
        _log("could not derive PR changed files; widening to ALL")
        return ALL
    if event_name == "push":
        default = _pushed_default_branch(event)
        if default:
            _log(
                f"push to default branch {default!r}: scanning everything so the "
                "code-scanning alert set for the ref is never narrowed by a partial upload"
            )
            return ALL
        before, after = event.get("before"), event.get("after")
        if not before or before == ZERO_SHA or not after:
            _log("push without a usable before/after pair (new branch?); widening to ALL")
            return ALL
        files = _git_diff(before, after)
        return sorted(set(files)) if files is not None else ALL
    return ALL  # schedule, workflow_dispatch, release, ...


def changed_files() -> Changed:
    for source in (from_env, from_github_event):
        result = source()
        if result is not None:
            return result
    return ALL


def is_all(changed: Changed) -> bool:
    return isinstance(changed, str) and changed == ALL


def any_match(changed: Changed, pattern: re.Pattern[str]) -> bool:
    if is_all(changed):
        return True
    return any(pattern.search(p) for p in changed)


def opengrep_targets(changed: Changed, root: Path) -> list[str] | None:
    """Concrete file list for a changed-file scan, or None for a full scan."""
    if is_all(changed):
        return None
    targets = [
        p
        for p in changed
        if p.lower().endswith(OPENGREP_EXT) or Path(p).name.startswith("Dockerfile")
    ]
    return [p for p in targets if (root / p).is_file()]


def describe(changed: Changed) -> str:
    return "ALL (full scan)" if is_all(changed) else f"{len(changed)} changed file(s)"


def write_list(changed: Changed, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(ALL + "\n" if is_all(changed) else "\n".join(changed) + "\n", encoding="utf-8")


def read_list(src: str | Path) -> Changed:
    text = Path(src).read_text(encoding="utf-8")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if len(lines) == 1 and lines[0].upper() == ALL:
        return ALL
    return lines


def filter_sequence(items: Sequence[str]) -> list[str]:
    return [i for i in items if i]
