"""propagate.yml must be able to run for real on Actions -- and stay safe while it does.

Every release through v0.1.10 was fanned out from a laptop: the workflow's only credential,
TOOLCHAIN_PROPAGATE_TOKEN, never existed on the repository, and the Propagate step exited 0
without saying much. These checks pin the shape that fixes that, and the trust boundaries
around it: one step decides the credential mode from presence booleans computed in the
expression layer (no secret value enters its shell), the App-token mint and the Propagate
step gate on that mode, the PAT enters the Propagate step's env only in pat mode, the minted
token is narrowed to exactly the permissions the fan-out needs, a published release is
refused unless its commit is reachable from main and its __version__ equals the tag, every
action is SHA-pinned, and no run body can echo a token. PyYAML drops comments, so the
`# vX.Y.Z` pin comments are checked on the raw text and cross-counted against the parsed
steps so no `uses:` line is missed.
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
GUARD = "Refuse to fan out a release whose __version__ doesn't match its own tag"
MINT = "Mint a scoped App installation token"

_PINNED_USES_RE = re.compile(r"^\s*-?\s*uses:\s*\S+@[0-9a-f]{40}\s+#\s*v\d+\.\d+\.\d+\s*$")
# A token-valued reference inside `${{ }}`: a secret, the default token, or a minted token --
# unless it is the left operand of a comparison, which yields a boolean, not the value. The
# `\b` stops `\w+` backtracking into a shorter name to dodge the lookahead.
_TOKEN_REF_RE = re.compile(
    r"(secrets\.\w+\b|github\.token\b|steps\.[\w-]+\.outputs\.token\b)(?!\s*(?:!=|==))"
)


def _holds_token(value: object) -> bool:
    return bool(_TOKEN_REF_RE.search(str(value)))


def _step(*, step_id: str | None = None, name: str | None = None) -> dict:
    for step in STEPS:
        if step_id is not None and step.get("id") == step_id:
            return step
        if name is not None and step.get("name") == name:
            return step
    have = [s.get("id") or s.get("name") for s in STEPS]
    raise AssertionError(f"no step with id={step_id!r} name={name!r}; have {have}")


def _label(step: dict) -> str:
    return step.get("name") or step.get("id")


def _token_keys(step: dict, mapping: str) -> list[str]:
    return sorted(k for k, v in (step.get(mapping) or {}).items() if _holds_token(v))


def _token_env_names() -> set[str]:
    names = {"GH_TOKEN"}  # also exported inside the Propagate run body, not only via env:
    for step in STEPS:
        names.update(_token_keys(step, "env"))
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
    # the job needs nothing from GITHUB_TOKEN beyond that: the release guard reads the compare
    # API with it, and all writes go through the App/PAT token
    assert "permissions" not in DOC["jobs"]["propagate"]


def test_triggers_are_release_published_and_dispatch_with_tag_repos_dry_run():
    triggers = DOC.get("on") or DOC[True]  # PyYAML 1.1 reads a bare `on:` key as boolean True
    assert triggers["release"] == {"types": ["published"]}
    assert set(triggers["workflow_dispatch"]["inputs"]) == {"tag", "repos", "dry_run"}
    assert "github.event_name == 'release'" in _step(name=GUARD)["if"]


def test_release_guard_refuses_a_tag_whose_commit_is_not_on_main():
    guard = _step(name=GUARD)
    assert "github.event_name == 'release'" in guard["if"]
    # the compare call needs only the read-only default token; no fan-out credential here
    default_expr = "${{ github.token }}"
    assert guard["env"]["GH_TOKEN"] == default_expr
    assert _token_keys(guard, "env") == ["GH_TOKEN"]
    run = guard["run"]
    compare = 'gh api "repos/${GITHUB_REPOSITORY}/compare/main...${GITHUB_SHA}" --jq .status'
    assert compare in run
    # identical / behind = GITHUB_SHA is reachable from main; every other status is refused
    assert re.search(r"^\s*identical\|behind\)\s*;;\s*$", run, re.M), run
    assert re.search(r"^\s*\*\)\s*$", run, re.M), run
    assert "::error title=propagate::" in run and "exit 1" in run
    assert "already merged to main" in run
    # the checkout is shallow: ancestry must come from the API, never from local git
    assert "merge-base" not in run and "--contains" not in run
    # the __version__ check survives, and runs AFTER the ancestry check -- importing the
    # package is the first thing here that executes code from the (unreviewed?) checkout
    version_import = "from thyn_security_toolchain import __version__"
    assert version_import in run and '[ "$installed" != "$TAG" ]' in run
    assert run.index(compare) < run.index(version_import)


def test_creds_step_tests_secret_presence_in_expressions_and_only_outputs_a_mode():
    creds = _step(step_id="creds")
    app_id, app_key = APP_SECRETS
    assert creds["env"] == {
        "HAS_APP": f"${{{{ secrets.{app_id} != '' && secrets.{app_key} != '' }}}}",
        "HAS_PAT": f"${{{{ secrets.{PAT_CREDENTIAL} != '' }}}}",
    }, creds["env"]
    # booleans only: no secret value enters this shell
    assert _token_keys(creds, "env") == []
    run = creds["run"]
    assert '[ "$HAS_APP" = "true" ]' in run and '[ "$HAS_PAT" = "true" ]' in run
    assert 'echo "mode=$mode" >> "$GITHUB_OUTPUT"' in run
    # app wins over pat; pat over none -- in that order
    assert run.index("mode=app") < run.index("mode=pat") < run.index("mode=none")


def test_mint_step_is_gated_on_creds_and_requests_least_privilege():
    mint = _step(step_id="app-token")
    assert mint["name"] == MINT
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
    # an allow-list of the two credentialed modes, not `!= 'none'`: an empty or unexpected
    # mode must never run the fan-out
    assert prop["if"] == "steps.creds.outputs.mode == 'app' || steps.creds.outputs.mode == 'pat'"
    env = prop["env"]
    assert env["MODE"] == "${{ steps.creds.outputs.mode }}"
    minted = "${{ steps.app-token.outputs.token }}"
    assert env["APP_TOKEN"] == minted
    # the PAT enters this process only when it is the credential in use
    assert env["PAT"] == (
        f"${{{{ steps.creds.outputs.mode == 'pat' && secrets.{PAT_CREDENTIAL} || '' }}}}"
    )
    run = prop["run"]
    # the token reaches git via the gh credential helper, never via a remote URL
    assert run.index("gh auth setup-git") < run.index("python scripts/propagate.py")
    assert "x-access-token" not in run and "@github.com/" not in run
    # App mode commits as the bot and drops the personal/assistant attribution
    assert "--no-attribution" in run and "[bot]" in run
    assert "--git-user" in run and "--git-email" in run
    # a configured-but-broken App is an error, not another silent green run
    assert "::error title=propagate::" in run and "exit 1" in run


def test_secret_values_reach_only_the_mint_action_and_the_propagate_step():
    # env: a token is placed in a shell's environment by exactly two steps -- the release
    # guard (the read-only default token) and Propagate (the minted token, the gated PAT)
    token_env = {_label(s): _token_keys(s, "env") for s in STEPS if _token_keys(s, "env")}
    assert token_env == {GUARD: ["GH_TOKEN"], "Propagate": ["APP_TOKEN", "PAT"]}, token_env
    # with: only the mint action receives the App secrets
    token_with = {_label(s): _token_keys(s, "with") for s in STEPS if _token_keys(s, "with")}
    assert token_with == {MINT: ["app-id", "private-key"]}, token_with
    # cross-count against the raw text so no `secrets.*` reference hides outside env:/with:
    code = [ln for ln in TEXT.splitlines() if not ln.lstrip().startswith("#")]
    raw = sum(ln.count("secrets.") for ln in code)
    parsed = sum(
        str(v).count("secrets.")
        for s in STEPS
        for mapping in ("env", "with")
        for v in (s.get(mapping) or {}).values()
    )
    assert raw == parsed == 6, (raw, parsed)


def test_no_run_body_echoes_a_token_holding_variable():
    names = _token_env_names()
    assert {"GH_TOKEN", "APP_TOKEN", "PAT"} <= names, names
    assert not ({"HAS_APP", "HAS_PAT"} & names), names  # booleans, not tokens
    expansions = re.compile(r"\$\{?(" + "|".join(sorted(names)) + r")\b")
    offenders = []
    for step in STEPS:
        for line in (step.get("run") or "").splitlines():
            if re.search(r"\b(echo|printf)\b", line) and expansions.search(line):
                offenders.append((_label(step), line.strip()))
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


def test_readme_documents_where_secrets_are_read_and_the_main_ancestry_rule():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    heading = "## Running propagate from GitHub Actions"
    assert heading in readme
    section = readme.split(heading, 1)[1].split("\n## ", 1)[0]
    assert "${{ secrets.NAME != '' }}" in section
    assert "only when it is the credential in use" in section
    assert "reachable from `main`" in section
    assert "`identical` or `behind`" in section
