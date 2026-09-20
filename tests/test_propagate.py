"""propagate.py keeps existing callers compatible with the callee they are being bumped to."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("propagate", REPO / "scripts" / "propagate.py")
propagate = importlib.util.module_from_spec(spec)
sys.modules["propagate"] = propagate
spec.loader.exec_module(propagate)

SHA_OLD = "a" * 40
SHA_NEW = "b" * 40

V010_CALLER = f"""name: security

permissions:
  contents: read

jobs:
  full:
    uses: thyn-ai/security-toolchain/.github/workflows/security-full.yml@{SHA_OLD} # v0.1.0
    permissions:
      contents: read
      security-events: write
      pull-requests: read
    with:
      overlay: python-uv
      mode: advisory
"""


def test_bump_adds_permissions_the_new_callee_requires():
    out = propagate.upsert_workflow(V010_CALLER, "full", SHA_NEW, "v0.1.1", "python-uv", "advisory")
    assert f"@{SHA_NEW} # v0.1.1" in out and SHA_OLD not in out
    job_block = out.split("    permissions:\n", 1)[1].split("    with:", 1)[0]
    assert "      actions: read" in job_block, out
    # the top-level (workflow) permissions block is left alone
    assert out.split("jobs:")[0].count("actions:") == 0
    assert "      overlay: python-uv" in out and "      mode: advisory" in out


def test_bump_is_idempotent_and_matches_the_template_permissions():
    rendered = (
        (REPO / "templates" / "security.yml")
        .read_text()
        .format(sha=SHA_OLD, tag="v0.1.0", overlay="site", mode="ratchet")
    )
    once = propagate.upsert_workflow(rendered, "full", SHA_NEW, "v0.1.1", "site", "ratchet")
    twice = propagate.upsert_workflow(once, "full", SHA_NEW, "v0.1.1", "site", "ratchet")
    assert once == twice
    assert once.count("actions: read") == 1
    # every permission the template grants must be in the carry-forward list, and vice versa
    template_perms = {
        ln.strip().split(":")[0]
        for ln in rendered.split("    permissions:\n", 1)[1].split("    with:", 1)[0].splitlines()
        if ln.strip()
    }
    required = {p.split(":")[0] for p in propagate._REQUIRED_CALLER_PERMISSIONS["full"]}
    assert template_perms == required, (template_perms, required)


def test_smoke_callers_are_not_given_sarif_permissions():
    rendered = (
        (REPO / "templates" / "security-smoke.yml")
        .read_text()
        .format(sha=SHA_OLD, tag="v0.1.0", mode="advisory")
    )
    out = propagate.upsert_workflow(rendered, "smoke", SHA_NEW, "v0.1.1", "smoke", "advisory")
    assert "actions:" not in out and "security-events" not in out
    assert f"@{SHA_NEW} # v0.1.1" in out


def test_new_precommit_config_ends_with_exactly_one_newline():
    block = propagate.render_block("v0.1.1", "python-uv")
    for python in (False, True):
        out = propagate.upsert_block(None, block, python, "v0.12.0")
        assert out.endswith("# thyn-security-toolchain:end\n"), out[-80:]
        assert not out.endswith("\n\n")
        assert "\n\n\n" not in out
        # re-applying to the generated file is a no-op (block-replace path)
        assert propagate.upsert_block(out, block, python, "v0.12.0") == out


def _on_block(text: str) -> str:
    return propagate._ON_BLOCK_RE.search(text).group(0)


def _rendered(name: str, **fields: str) -> str:
    return (REPO / "templates" / name).read_text().format(**fields)


@pytest.mark.parametrize(
    "name,kind,fields",
    [
        ("security.yml", "full", {"overlay": "site", "mode": "advisory"}),
        ("security-smoke.yml", "smoke", {"mode": "advisory"}),
    ],
    ids=["full", "smoke"],
)
def test_bump_adds_the_merge_group_trigger_the_fleet_callers_lack(name, kind, fields):
    """Every caller rendered before v0.1.13 triggers on pull_request and push only. The bump
    inserts merge_group right after pull_request, so the caller's `on:` block comes out equal
    to what the current template renders -- and a second bump changes nothing."""
    template = _rendered(name, sha=SHA_OLD, tag="v0.1.12", **fields)
    assert "\n  merge_group:\n" in template
    fleet_caller = template.replace("\n  merge_group:\n", "\n", 1)
    assert "merge_group:" not in _on_block(fleet_caller)
    overlay = fields.get("overlay", "smoke")
    out = propagate.upsert_workflow(fleet_caller, kind, SHA_NEW, "v0.1.13", overlay, fields["mode"])
    assert f"@{SHA_NEW} # v0.1.13" in out and SHA_OLD not in out
    assert _on_block(out) == _on_block(template)
    assert propagate.upsert_workflow(out, kind, SHA_NEW, "v0.1.13", overlay, fields["mode"]) == out


def _caller_with(pull_request_filters: str) -> str:
    return (
        "name: security\n\non:\n  pull_request:\n"
        + pull_request_filters
        + "  push:\n    branches: [main]\n\n"
        + V010_CALLER.split("\n", 2)[2]
    )


@pytest.mark.parametrize(
    "filters,mirrored",
    [
        ("", ""),
        ("    branches: [main, release/*]\n", "    branches: [main, release/*]\n"),
        (
            "    branches:\n      - main\n      - release/*\n",
            "    branches:\n      - main\n      - release/*\n",
        ),
        ("    branches-ignore: [wip/**]\n", "    branches-ignore: [wip/**]\n"),
        # a merge group takes no `types` or `paths` filter: only the branch filter is mirrored
        ("    types: [opened, synchronize]\n    paths: ['src/**']\n", ""),
        (
            "    types: [opened]\n    branches: [main]\n    paths: ['src/**']\n",
            "    branches: [main]\n",
        ),
    ],
    ids=["none", "flow", "block", "ignore", "types-and-paths-only", "mixed"],
)
def test_merge_group_mirrors_only_the_pull_request_branch_filter(filters, mirrored):
    out = propagate.add_merge_group_trigger(_caller_with(filters))
    assert ("  pull_request:\n" + filters + "  merge_group:\n" + mirrored + "  push:\n") in out, out
    assert out.count("merge_group:") == 1


@pytest.mark.parametrize(
    "text",
    [
        "on: [push, pull_request]\n\njobs: {}\n",  # flow style: not this reader's shape
        "on:\n  push:\n    branches: [main]\n\njobs: {}\n",  # nothing to sit next to
        "on:\n  pull_request:\n  merge_group:\n  push:\n\njobs: {}\n",  # already there
        '"on":\n  merge_group:\n    branches: [main]\n  pull_request:\n\njobs: {}\n',
        "jobs: {}\n",
    ],
    ids=["flow", "no-pull-request", "present", "present-quoted-key", "no-on"],
)
def test_callers_already_triggering_or_of_another_shape_are_left_alone(text):
    assert propagate.add_merge_group_trigger(text) == text
