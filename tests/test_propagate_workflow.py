"""propagate.yml must be able to run for real on Actions -- and stay safe while it does.

Every release through v0.1.10 was fanned out from a laptop: the workflow's only credential,
TOOLCHAIN_PROPAGATE_TOKEN, never existed on the repository, and the Propagate step exited 0
without saying much. These checks pin the shape that fixes that: one step decides the
credential mode, the App-token mint and the Propagate step gate on it, the minted token is
narrowed to exactly the permissions the fan-out needs, every action is SHA-pinned, and no
run body can echo a token. PyYAML drops comments, so the `# vX.Y.Z` pin comments are checked
on the raw text and cross-counted against the parsed steps so no `uses:` line is missed.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "propagate.yml"
TEXT = WORKFLOW.read_text(encoding="utf-8")
DOC = yaml.safe_load(TEXT)
STEPS = DOC["jobs"]["propagate"]["steps"]

MINT_ACTION = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
TOKEN_PERMISSIONS = {
    "permission-contents": "write",
    "permission-pull-requests": "write",
    "permission-workflows": "write",
    "permission-metadata": "read",
}
APP_SECRETS = ("ALGENTA_SDK_SYNC_APP_ID", "ALGENTA_SDK_SYNC_APP_PRIVATE_KEY")
PAT_CREDENTIAL = "TOOLCHAIN_PROPAGATE_TOKEN"

_PINNED_USES_RE = re.compile(r"^\s*-?\s*uses:\s*\S+@[0-9a-f]{40}\s+#\s*v\d+\.\d+\.\d+\s*$")
# an env var whose value is a secret or a minted token
_TOKEN_VALUE_RE = re.compile(r"\$\{\{\s*(secrets\.\w+|steps\.[\w-]+\.outputs\.token)\s*\}\}")


def _step(*, step_id: str | None = None, name: str | None = None) -> dict:
    for step in STEPS:
        if step_id is not None and step.get("id") == step_id:
            return step
        if name is not None and step.get("name") == name:
            return step
    have = [s.get("id") or s.get("name") for s in STEPS]
    raise AssertionError(f"no step with id={step_id!r} name={name!r}; have {have}")


def _secret_holding_env_names() -> set[str]:
    names = {"GH_TOKEN", "APP_PRIVATE_KEY"}
    for step in STEPS:
        for key, value in (step.get("env") or {}).items():
            if _TOKEN_VALUE_RE.search(str(value)):
                names.add(key)
    return names


def test_every_uses_is_pinned_to_a_sha_with_a_version_comment():
    raw = [ln for ln in TEXT.splitlines() if re.match(r"^\s*-?\s*uses:", ln)]
    parsed = [s["uses"] for s in STEPS if "uses" in s]
    assert parsed and len(raw) == len(parsed), (raw, parsed)
    assert MINT_ACTION in parsed
    for line in raw:
        assert _PINNED_USES_RE.match(line), f"not `@<40-hex sha> # vX.Y.Z`: {line.strip()}"


def test_top_level_permissions_are_exactly_contents_read():
    assert DOC["permissions"] == {"contents": "read"}
    # the job needs nothing from GITHUB_TOKEN either: all writes go through the App/PAT token
    assert "permissions" not in DOC["jobs"]["propagate"]


def test_triggers_are_release_published_and_dispatch_with_tag_repos_dry_run():
    triggers = DOC.get("on") or DOC[True]  # PyYAML 1.1 reads a bare `on:` key as boolean True
    assert triggers["release"] == {"types": ["published"]}
    assert set(triggers["workflow_dispatch"]["inputs"]) == {"tag", "repos", "dry_run"}
    guard = _step(name="Refuse to fan out a release whose __version__ doesn't match its own tag")
    assert "github.event_name == 'release'" in guard["if"]


def test_creds_step_reads_exactly_the_three_secrets_and_only_outputs_a_mode():
    creds = _step(step_id="creds")
    values = set(creds["env"].values())
    expected = {f"${{{{ secrets.{name} }}}}" for name in (*APP_SECRETS, PAT_CREDENTIAL)}
    assert values == expected, values
    run = creds["run"]
    assert 'echo "mode=$mode" >> "$GITHUB_OUTPUT"' in run
    # app wins over pat; pat over none -- in that order
    assert run.index("mode=app") < run.index("mode=pat") < run.index("mode=none")


def test_mint_step_is_gated_on_creds_and_requests_least_privilege():
    mint = _step(step_id="app-token")
    assert mint["uses"] == MINT_ACTION
    assert "steps.creds.outputs.mode == 'app'" in mint["if"]
    # a mint failure must fall through to the Propagate step's explanation, not a bare error
    assert mint.get("continue-on-error") is True
    with_ = mint["with"]
    assert with_["app-id"] == f"${{{{ secrets.{APP_SECRETS[0]} }}}}"
    assert with_["private-key"] == f"${{{{ secrets.{APP_SECRETS[1]} }}}}"
    assert with_["owner"] == "thyn-ai"
    # documented decision: scope by installation, never by a static repo list
    assert "repositories" not in with_
    granted = {k: v for k, v in with_.items() if k.startswith("permission-")}
    assert granted == TOKEN_PERMISSIONS, granted


def test_propagate_step_is_gated_on_creds_and_authenticates_git_through_gh():
    prop = _step(name="Propagate")
    assert "steps.creds.outputs.mode" in prop["if"]
    env = prop["env"]
    assert env["MODE"] == "${{ steps.creds.outputs.mode }}"
    minted = "${{ steps.app-token.outputs.token }}"
    assert env["APP_TOKEN"] == minted
    assert env["PAT"] == f"${{{{ secrets.{PAT_CREDENTIAL} }}}}"
    run = prop["run"]
    # the token reaches git via the gh credential helper, never via a remote URL
    assert run.index("gh auth setup-git") < run.index("python scripts/propagate.py")
    assert "x-access-token" not in run and "@github.com/" not in run
    # App mode commits as the bot and drops the personal/assistant attribution
    assert "--no-attribution" in run and "[bot]" in run
    assert "--git-user" in run and "--git-email" in run
    # a configured-but-broken App is an error, not another silent green run
    assert "::error title=propagate::" in run and "exit 1" in run


def test_no_run_body_echoes_a_token_holding_variable():
    names = _secret_holding_env_names()
    assert {"GH_TOKEN", "APP_PRIVATE_KEY", "APP_TOKEN", "PAT"} <= names, names
    expansions = re.compile(r"\$\{?(" + "|".join(sorted(names)) + r")\b")
    offenders = []
    for step in STEPS:
        for line in (step.get("run") or "").splitlines():
            if re.search(r"\b(echo|printf)\b", line) and expansions.search(line):
                offenders.append((step.get("name") or step.get("id"), line.strip()))
    assert not offenders, offenders


def test_every_credential_mode_writes_a_step_summary_and_points_at_the_readme():
    skip = _step(name="Explain the skip (no credentials configured)")
    assert skip["if"] == "steps.creds.outputs.mode == 'none'"
    assert "::notice title=propagate::" in skip["run"]
    for secret in (*APP_SECRETS, PAT_CREDENTIAL):
        assert secret in skip["run"], f"skip notice does not name {secret}"
    for step in (skip, _step(name="Propagate")):
        assert "GITHUB_STEP_SUMMARY" in step["run"], step["name"]
        assert "README" in step["run"], step["name"]
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert "## Running propagate from GitHub Actions" in readme
