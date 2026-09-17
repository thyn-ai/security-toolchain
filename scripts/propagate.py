#!/usr/bin/env python3
"""Fan a security-toolchain release out to every repository in fleet.json.

For each repository this opens ONE pull request that touches only:

* the marker-delimited block in ``.pre-commit-config.yaml`` (created if absent, together
  with a minimal config for repositories that have none), and
* the ``uses: thyn-ai/security-toolchain/...@<sha> # <tag>`` pin in
  ``.github/workflows/security.yml`` (created from the template if absent).

Existing ``overlay``/``mode`` choices in a caller workflow are preserved; only the pin
moves. Repositories that are mirrored from elsewhere declare ``sync_safe_paths`` and the
script refuses to write outside them.

Runs anywhere ``gh`` is authenticated (a laptop, or propagate.yml with a token).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FLEET = ROOT / "fleet.json"
TEMPLATES = ROOT / "templates"
BEGIN = "# thyn-security-toolchain:begin"
END = "# thyn-security-toolchain:end"
TOOLCHAIN_REPO = "thyn-ai/security-toolchain"

_USES_RE = re.compile(
    r"(uses:\s*thyn-ai/security-toolchain/\.github/workflows/security-(?:full|smoke)\.ya?ml@)"
    r"[^\s#]+([ \t]*#[ \t]*[^\s]+)?"
)
_ATTRIBUTION = "\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)"
_TRAILER = "\n\nCo-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"


def sh(cmd: list[str], cwd: Path | None = None, check: bool = True) -> str:
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise SystemExit(f"$ {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}")
    return proc.stdout.strip()


def resolve_tag(tag: str) -> str:
    """Return the commit SHA a tag points at (dereferencing annotated tags)."""
    ref = json.loads(sh(["gh", "api", f"repos/{TOOLCHAIN_REPO}/git/ref/tags/{tag}"]))
    sha, kind = ref["object"]["sha"], ref["object"]["type"]
    if kind == "tag":
        sha = json.loads(sh(["gh", "api", f"repos/{TOOLCHAIN_REPO}/git/tags/{sha}"]))["object"][
            "sha"
        ]
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SystemExit(f"tag {tag} did not resolve to a commit sha: {sha!r}")
    return sha


def latest_tag() -> str:
    return json.loads(sh(["gh", "api", f"repos/{TOOLCHAIN_REPO}/releases/latest"]))["tag_name"]


def render_block(rev: str, overlay: str) -> str:
    return (
        (TEMPLATES / "pre-commit-block.yaml")
        .read_text(encoding="utf-8")
        .format(rev=rev, overlay=overlay)
    )


def upsert_block(existing: str | None, block: str, python: bool, ruff_rev: str) -> str:
    if existing is None:
        extra = ""
        if python:
            extra = (
                (TEMPLATES / "extra-hooks.python.yaml")
                .read_text(encoding="utf-8")
                .format(ruff_rev=ruff_rev)
            )
        rendered = (
            (TEMPLATES / "pre-commit-config.yaml")
            .read_text(encoding="utf-8")
            .format(extra_hooks=extra.rstrip("\n"), block=block.rstrip("\n"))
        )
        # Exactly one trailing newline: the generated file must pass its own end-of-file-fixer.
        return re.sub(r"\n{3,}", "\n\n", rendered).rstrip("\n") + "\n"
    text = existing
    if BEGIN in text and END in text:
        start = text.index(BEGIN)
        start = text.rfind("\n", 0, start) + 1
        end = text.index(END) + len(END)
        end = text.find("\n", end)
        end = len(text) if end < 0 else end + 1
        return text[:start] + block + text[end:]
    if not re.search(r"(?m)^default_install_hook_types:", text):
        text = "default_install_hook_types: [pre-commit, pre-push]\n" + text
    if not re.search(r"(?m)^repos:", text):
        text = text.rstrip("\n") + "\nrepos:\n"
    return text.rstrip("\n") + "\n" + block


def upsert_workflow(
    existing: str | None, kind: str, sha: str, tag: str, overlay: str, mode: str
) -> str:
    if existing is not None and _USES_RE.search(existing):
        text = _USES_RE.sub(lambda m: f"{m.group(1)}{sha} # {tag}", existing)
        return _carry_forward_permissions(text, kind)
    template = TEMPLATES / ("security.yml" if kind == "full" else "security-smoke.yml")
    return template.read_text(encoding="utf-8").format(sha=sha, tag=tag, overlay=overlay, mode=mode)


# A caller job may grant no less than the reusable workflow's job requests, or GitHub
# rejects the run at startup ("requesting X, but is only allowed none"). When a release
# adds a permission to the callee, every existing caller must gain it in the same bump.
_REQUIRED_CALLER_PERMISSIONS = {
    "full": (
        "contents: read",
        "security-events: write",
        "pull-requests: read",
        "actions: read # SARIF upload needs it while this repository is private",
    ),
    "smoke": ("contents: read",),
}
_PERMISSIONS_BLOCK_RE = re.compile(
    r"(?m)^(?P<indent>[ \t]+)permissions:\n(?P<body>(?:(?P=indent)[ \t]+\S[^\n]*\n)+)"
)


def _carry_forward_permissions(text: str, kind: str) -> str:
    """Ensure the caller job's `permissions:` block lists everything the callee needs."""
    m = _PERMISSIONS_BLOCK_RE.search(text)
    if not m:
        return text
    indent = m.group("indent")
    body = m.group("body")
    present = {ln.strip().split(":")[0] for ln in body.splitlines() if ln.strip()}
    missing = [p for p in _REQUIRED_CALLER_PERMISSIONS[kind] if p.split(":")[0] not in present]
    if not missing:
        return text
    inner = body.splitlines()[0][len(indent) :]
    inner_indent = inner[: len(inner) - len(inner.lstrip())]
    addition = "".join(f"{indent}{inner_indent}{p}\n" for p in missing)
    return text[: m.end()] + addition + text[m.end() :]


def plan(repo_dir: Path, cfg: dict, defaults: dict, tag: str, sha: str) -> list[tuple[Path, str]]:
    overlay = cfg["overlay"]
    mode = cfg.get("mode", defaults["mode"])
    kind = cfg.get("workflow", defaults["workflow"])
    changes: list[tuple[Path, str]] = []

    pc = repo_dir / ".pre-commit-config.yaml"
    pc_text = pc.read_text(encoding="utf-8") if pc.is_file() else None
    new_pc = upsert_block(
        pc_text, render_block(tag, overlay), cfg.get("python", False), defaults["ruff_rev"]
    )
    if new_pc != pc_text:
        changes.append((pc, new_pc))

    wf = repo_dir / ".github" / "workflows" / "security.yml"
    wf_text = wf.read_text(encoding="utf-8") if wf.is_file() else None
    new_wf = upsert_workflow(wf_text, kind, sha, tag, overlay, mode)
    if new_wf != wf_text:
        changes.append((wf, new_wf))

    safe = cfg.get("sync_safe_paths")
    if safe:
        for path, _ in changes:
            rel = str(path.relative_to(repo_dir))
            if not any(rel == s or rel.startswith(s) for s in safe):
                raise SystemExit(
                    f"{repo_dir.name}: refusing to touch {rel}; not in sync_safe_paths {safe}"
                )
    return changes


def propagate(
    name: str, cfg: dict, defaults: dict, tag: str, sha: str, args: argparse.Namespace
) -> str:
    org = defaults.get("org", "thyn-ai")
    with tempfile.TemporaryDirectory(prefix=f"propagate-{name}-") as td:
        repo_dir = Path(td) / name
        sh(["gh", "repo", "clone", f"{org}/{name}", str(repo_dir), "--", "--depth", "1", "--quiet"])
        default_branch = sh(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_dir)
        changes = plan(repo_dir, cfg, defaults, tag, sha)
        if not changes:
            return f"{name}: already at {tag}"
        branch = f"chore/security-toolchain-{tag}"
        if args.dry_run:
            return f"{name}: would change " + ", ".join(
                str(p.relative_to(repo_dir)) for p, _ in changes
            )
        sh(["git", "checkout", "-q", "-b", branch], cwd=repo_dir)
        for path, text in changes:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            sh(["git", "add", "--", str(path.relative_to(repo_dir))], cwd=repo_dir)
        sh(["git", "config", "user.name", args.git_user], cwd=repo_dir)
        sh(["git", "config", "user.email", args.git_email], cwd=repo_dir)
        title = f"chore(security): thyn-ai/security-toolchain {tag}"
        body = (
            f"Pins the security toolchain to `{tag}` (`{sha}`) for the pre-commit/pre-push hooks\n"
            "and the CI gate.\n\n"
            f"- overlay `{cfg['overlay']}`, mode `{cfg.get('mode', defaults['mode'])}`\n"
            "- advisory mode never fails CI; ratchet fails only on findings not in\n"
            "  `security/baseline/`\n"
            "- baselines are measured on CI via `workflow_dispatch` → `measure_baseline`\n\n"
            f"Opened by `scripts/propagate.py` from {TOOLCHAIN_REPO}."
        )
        message = title + "\n\n" + body + (_TRAILER if args.attribution else "")
        sh(["git", "commit", "-q", "-m", message], cwd=repo_dir)
        sh(["git", "push", "-q", "-u", "origin", branch], cwd=repo_dir)
        pr_body = body + (_ATTRIBUTION if args.attribution else "")
        url = sh(
            [
                "gh",
                "pr",
                "create",
                "--base",
                default_branch,
                "--head",
                branch,
                "--title",
                title,
                "--body",
                pr_body,
            ],
            cwd=repo_dir,
        )
        if cfg.get("auto_merge", defaults.get("auto_merge", False)) and not args.no_auto_merge:
            sh(["gh", "pr", "merge", "--auto", "--squash", url], cwd=repo_dir, check=False)
        return f"{name}: {url}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--tag", help="toolchain tag to pin (default: latest release)")
    ap.add_argument("--repos", help="comma list of repository names to limit to")
    ap.add_argument("--wave", type=int, help="limit to repositories in this rollout wave")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-auto-merge", action="store_true")
    ap.add_argument("--no-attribution", dest="attribution", action="store_false")
    ap.add_argument("--git-user", default="angelatgithub")
    ap.add_argument("--git-email", default="79715912+angelatgithub@users.noreply.github.com")
    args = ap.parse_args(argv)

    fleet = json.loads(FLEET.read_text(encoding="utf-8"))
    defaults = fleet["defaults"]
    tag = args.tag or latest_tag()
    sha = resolve_tag(tag)
    print(f"propagating {tag} ({sha})", file=sys.stderr)

    selected = fleet["repos"]
    if args.repos:
        wanted = {r.strip() for r in args.repos.split(",") if r.strip()}
        unknown = wanted - set(selected)
        if unknown:
            raise SystemExit(f"not in fleet.json: {sorted(unknown)}")
        selected = {k: v for k, v in selected.items() if k in wanted}
    if args.wave is not None:
        selected = {k: v for k, v in selected.items() if v.get("wave") == args.wave}

    failures = 0
    for name, cfg in selected.items():
        if cfg.get("skip"):
            print(f"{name}: skipped -- {cfg['skip']}")
            continue
        try:
            print(propagate(name, cfg, defaults, tag, sha, args))
        except SystemExit as exc:
            failures += 1
            print(f"{name}: FAILED\n{exc}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
