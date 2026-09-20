"""Changed-file derivation for PR-scoped scanning (fail-closed to a full scan).

Mirrors the engine's blast-radius selector in ``.github/workflows/ci.yml``: on a
``pull_request`` event the authoritative list is ``GET /pulls/{n}/files`` (needs no
local history); on ``push`` to a non-default branch it is ``git diff before...after``;
anything that cannot be derived with certainty returns ``ALL`` so the scan widens rather
than narrows.

A ``merge_group`` event is the same pull request one step later: the merge queue built a
temporary branch (``refs/heads/gh-readonly-queue/<base>/pr-<n>-<sha>``) holding the queue's
tip plus that pull request, and ``merge_group.base_sha``...``head_sha`` is exactly the pull
request's contribution to it. The group is scoped like the pull request it was built for --
its files from the API when the number can be read off ``head_ref``, otherwise the diff of
the two SHAs -- and widens to ``ALL`` when neither can be derived.

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

ALL = "ALL"
Changed = str | list[str]  # ALL or a concrete list

ZERO_SHA = "0" * 40
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# The temporary branch a merge queue builds a group on ends in ``pr-<number>-<base sha>``; the
# base branch before it may itself contain slashes, so the number is read from the end.
_MERGE_GROUP_REF_RE = re.compile(r"/pr-([1-9][0-9]*)-[0-9a-f]{40}$")

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
    return _lines(p.read_text(encoding="utf-8"))


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
    if not (_SHA_RE.match(base) and _SHA_RE.match(head)):
        # Every event field that reaches here is a full commit SHA. Anything else is refused
        # before it becomes a git argument: a value starting with ``-`` would be read as an
        # option, and the fail-closed answer for an undecidable diff is a full scan anyway.
        _log(f"refusing git diff on non-SHA revisions {base!r}...{head!r}")
        return None
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


def _mapping(value: object) -> dict:
    """*value* when it is a JSON object, else an empty one (a missing field reads the same)."""
    return value if isinstance(value, dict) else {}


def _text(value: object) -> str:
    """*value* when it is a string, else empty (a field of the wrong type is a missing field)."""
    return value if isinstance(value, str) else ""


def merge_group_pull_number(head_ref: object) -> int | None:
    """The pull request a merge group was built for, read from ``merge_group.head_ref``.

    ``refs/heads/gh-readonly-queue/main/pr-104-<base sha>`` names #104; anything of another
    shape (or type) is None, and the caller falls through to the SHA diff.
    """
    m = _MERGE_GROUP_REF_RE.search(_text(head_ref))
    return int(m.group(1)) if m else None


def _pull_scope(number: object, base: str, head: str, repo: str, server: str, what: str) -> Changed:
    """Changed files of one pull request: its files from the API, else the diff, else ALL."""
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if isinstance(number, int) and number > 0 and token and repo:
        files = _api_pr_files(repo, number, token, server)
        if files is not None:
            return sorted(set(files))
    if base and head:
        files = _git_diff(base, head)
        if files is not None:
            return sorted(set(files))
    _log(f"could not derive {what} changed files; widening to ALL")
    return ALL


def _pushed_default_branch(event: dict) -> str | None:
    """Name of the default branch when the pushed ref *is* that branch, else None.

    The default branch comes from the event payload (``repository.default_branch``); the
    pushed ref from ``GITHUB_REF`` (falling back to the payload's ``ref``) or, when only
    the short name is available, from ``GITHUB_REF_NAME``. A tag that happens to share
    the default branch's name (``GITHUB_REF_TYPE=tag``) does not count.
    """
    default = _text(_mapping(event.get("repository")).get("default_branch")).strip()
    if not default:
        return None
    ref = os.environ.get("GITHUB_REF") or _text(event.get("ref"))
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
    if not isinstance(event, dict):
        return ALL  # a payload that is not an object cannot name a diff; fail closed
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    if event_name in ("pull_request", "pull_request_target"):
        pull = _mapping(event.get("pull_request"))
        number = pull.get("number") or event.get("number")
        base = _text(_mapping(pull.get("base")).get("sha"))
        head = _text(_mapping(pull.get("head")).get("sha"))
        return _pull_scope(number, base, head, repo, server, "PR")
    if event_name == "merge_group":
        group = _mapping(event.get("merge_group"))
        number = merge_group_pull_number(group.get("head_ref"))
        base, head = _text(group.get("base_sha")), _text(group.get("head_sha"))
        return _pull_scope(number, base, head, repo, server, "merge-group")
    if event_name == "push":
        default = _pushed_default_branch(event)
        if default:
            _log(
                f"push to default branch {default!r}: scanning everything so the "
                "code-scanning alert set for the ref is never narrowed by a partial upload"
            )
            return ALL
        before, after = _text(event.get("before")), _text(event.get("after"))
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


def _lines(text: str) -> list[str]:
    """The entries of a newline-separated list file: one path per line, blank lines dropped.

    Split on ``\\n`` only. ``str.splitlines`` would also split on form feed, the ASCII
    separators and the Unicode line/paragraph separators, all of which are legal inside a
    file name, so a path :func:`write_list` wrote as one line would read back as two.
    """
    return [ln.strip() for ln in text.split("\n") if ln.strip()]


def read_list(src: str | Path) -> Changed:
    lines = _lines(Path(src).read_text(encoding="utf-8"))
    if len(lines) == 1 and lines[0].upper() == ALL:
        return ALL
    return lines


def filter_sequence(items: Sequence[str]) -> list[str]:
    return [i for i in items if i]
