"""Contracts between the hook manifest, the CLI, the overlays and the templates.

Counts are derived from the files themselves, never hard-coded.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from thyn_security_toolchain import hooks
from thyn_security_toolchain.cli import build_parser

REPO = Path(__file__).resolve().parents[1]
HOOKS_YAML = REPO / ".pre-commit-hooks.yaml"
FLEET = REPO / "fleet.json"
SECURITY_FULL = REPO / ".github" / "workflows" / "security-full.yml"

_ID_RE = re.compile(r"^- id: ([\w-]+)$", re.M)
_ENTRY_RE = re.compile(r"^  entry: thyn-sec ([\w-]+)$", re.M)
_STAGES_RE = re.compile(r"^  stages: \[([^\]]+)\]$", re.M)


def _subcommands() -> set:
    parser = build_parser()
    sub = next(a for a in parser._actions if a.dest == "command")
    return set(sub.choices)


def test_every_hook_id_has_a_matching_cli_subcommand():
    text = HOOKS_YAML.read_text(encoding="utf-8")
    ids = _ID_RE.findall(text)
    entries = _ENTRY_RE.findall(text)
    assert ids and len(ids) == len(entries), "each hook must have exactly one thyn-sec entry"
    assert ids == entries, "hook id and CLI subcommand are the same word by convention"
    missing = set(ids) - _subcommands()
    assert not missing, f"hooks without a CLI implementation: {sorted(missing)}"


def test_full_gate_hooks_run_at_pre_push_and_fast_hooks_at_pre_commit():
    text = HOOKS_YAML.read_text(encoding="utf-8")
    blocks = re.split(r"(?m)^- id: ", text)[1:]
    stages = {b.split("\n", 1)[0]: _STAGES_RE.search(b).group(1) for b in blocks}
    pre_push = {k for k, v in stages.items() if v == "pre-push"}
    pre_commit = {k for k, v in stages.items() if v == "pre-commit"}
    manual = {k for k, v in stages.items() if v == "manual"}
    assert {"opengrep-full", "osv-scan", "trivy-config", "gitleaks-push"} <= pre_push
    assert {"gitleaks-staged", "opengrep-changed", "verify-toolchain", "actionlint"} <= pre_commit
    assert manual == {"security-fix-deps"}
    assert set(stages) == pre_push | pre_commit | manual


def test_every_overlay_resolves_and_respects_one_owner_per_category():
    names = hooks.overlay_names()
    assert names
    forbidden_prefixes = ("generic/secrets", "dockerfile/", "terraform/", "yaml/kubernetes")
    for name in names:
        packs, _ = hooks.resolve_overlay(name)
        assert packs, f"overlay {name} resolved to zero packs"
        for p in packs:
            assert not p.startswith(forbidden_prefixes), (
                f"overlay {name} includes {p}: secrets belong to gitleaks, IaC misconfig to trivy"
            )
        assert len(packs) == len(set(packs))


def test_template_block_is_delimited_and_uses_every_hook():
    block = (REPO / "templates" / "pre-commit-block.yaml").read_text(encoding="utf-8")
    assert "# thyn-security-toolchain:begin" in block and "# thyn-security-toolchain:end" in block
    ids = set(_ID_RE.findall(HOOKS_YAML.read_text(encoding="utf-8")))
    used = set(re.findall(r"- id: ([\w-]+)", block))
    assert used == ids, f"template block must list every hook exactly once; diff={ids ^ used}"
    assert "{rev}" in block and "{overlay}" in block


def test_caller_templates_pin_by_sha_with_tag_comment():
    for name in ("security.yml", "security-smoke.yml"):
        text = (REPO / "templates" / name).read_text(encoding="utf-8")
        pattern = (
            r"uses: thyn-ai/security-toolchain/\.github/workflows/"
            r"security-(full|smoke)\.yml@\{sha\} # \{tag\}"
        )
        assert re.search(pattern, text), name
        assert "permissions:" in text


def test_caller_templates_trigger_on_merge_group_next_to_pull_request():
    """A merge queue runs the checks it requires on `merge_group`; a caller triggering on
    `pull_request` and `push` only can never report `full / security gate` for a queued pull
    request, and the queue waits forever (thyn-ai/algenta-sdk)."""
    for name in ("security.yml", "security-smoke.yml"):
        text = (REPO / "templates" / name).read_text(encoding="utf-8")
        assert "\non:\n  pull_request:\n  merge_group:\n  push:\n" in text, name


def test_pnpm_monorepo_is_an_alias_of_python_javascript():
    """The pre-0.1.12 name stays resolvable for callers already propagated with it and can
    never drift from the pack set it names. thyn-ai/mojo-kernels#9 read the old name as a
    lockfile selector; it never was one (tests/test_osv_scope.py pins that seam)."""
    assert hooks.resolve_overlay("pnpm-monorepo") == hooks.resolve_overlay("python-javascript")
    spec = hooks.load_overlays()["pnpm-monorepo"]
    assert spec.get("extends") == ["python-javascript"]
    assert not spec.get("packs") and not spec.get("exclude_rules")


def test_every_fleet_overlay_resolves():
    fleet = json.loads(FLEET.read_text(encoding="utf-8"))
    known = set(hooks.overlay_names())
    for repo, cfg in fleet["repos"].items():
        assert cfg["overlay"] in known, f"fleet.json: {repo} -> unknown overlay {cfg['overlay']!r}"


def test_security_full_overlay_description_names_every_fleet_overlay():
    fleet = json.loads(FLEET.read_text(encoding="utf-8"))
    used = {cfg["overlay"] for cfg in fleet["repos"].values()}
    m = re.search(r'overlay:\n\s+description: "([^"]+)"', SECURITY_FULL.read_text(encoding="utf-8"))
    assert m, "security-full.yml overlay input has no description"
    for name in sorted(used):
        assert name in m.group(1), f"security-full.yml overlay description omits {name!r}"
