"""dependabot-auto-merge.yml: Dependabot pull requests land on their own -- and safely.

The reusable workflow runs on `pull_request_target`, `pull_request_review` and `push` with the
repository's secrets, so the shape held here is a trust boundary: nothing from the pull request
may execute (no checkout, no local action, no pull-request free-text in a shell -- the title is
admitted into one step's environment, matched against a grammar and never run), the App's
private key reaches exactly one action input per job, the minted token exactly the steps that act
with it, the default token stays read-only, every remote action is SHA-pinned, and the merge is
enabled with the App token rather than GITHUB_TOKEN for the reason the header comment cites from
GitHub's docs.

The Decide step is a pure function of its environment. It is run here, under bash, against the
cases in tests/data/dependabot_auto_merge_cases.json: an approved, thread-free, minor or patch
update is enabled (a requirement update's type comes from the lower bounds in its title, not from
fetch-metadata's misread of an upper-bound-first range); everything the workflow promises to skip
is skipped with a notice (majors, unclassified changes, no or non-APPROVED codna review, an
approval of another head, unresolved threads, drafts, forks, a human's existing auto-merge); an
auto-merge this App enabled is disarmed when its head or codna's verdict changed; a BEHIND pull
request that is or stays armed gets its branch update; a miscalled workflow is an error. Every
`skip "..."`, `disarm "..."` and `refuse "..."` in the script must be reached by at least one case
-- the lists of reasons are read from the script, not counted.

The sweep job's selection of pull requests is a jq filter; it is run here against fixture nodes.

The caller template is rendered the way propagate.py renders it and checked against the
pin-verifier and the shape a fleet repository must carry.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

from thyn_security_toolchain import verify

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "dependabot-auto-merge.yml"
TEMPLATE = REPO / "templates" / "dependabot-auto-merge.yml"
CASES = json.loads((REPO / "tests" / "data" / "dependabot_auto_merge_cases.json").read_text())
TEXT = WORKFLOW.read_text(encoding="utf-8")
DOC = yaml.safe_load(TEXT)
JOBS = DOC["jobs"]
ENABLE = JOBS["enable"]
SWEEP = JOBS["sweep"]
STEPS = ENABLE["steps"]
SWEEP_STEPS = SWEEP["steps"]
ALL_STEPS = STEPS + SWEEP_STEPS

SHA = "c" * 40
MINT_ACTION = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
METADATA_ACTION = "dependabot/fetch-metadata@25dd0e34f4fe68f24cc83900b1fe3fe149efef98"
TOKEN_PERMISSIONS = {
    "permission-contents": "write",
    "permission-pull-requests": "write",
    "permission-workflows": "write",
    "permission-metadata": "read",
}
JOB_PERMISSIONS = {"contents": "read", "pull-requests": "read"}
CALLER_TRIGGERS = {
    "pull_request_target": {"types": ["opened", "synchronize", "reopened"]},
    "pull_request_review": {"types": ["submitted"]},
    "push": {"branches": ["main"]},
}
# The caller's job condition, as YAML `>-` folds it: one line, single-spaced.
CALLER_IF = (
    "github.event_name == 'push' "
    "|| (github.event.pull_request.user.login == 'dependabot[bot]' "
    "&& (github.event_name != 'pull_request_review' "
    "|| github.event.review.user.login == 'codna-ai[bot]'))"
)
# The steps that act with the minted token, and the condition each acts under.
ACTING = (
    "steps.decide.outputs.decision == 'enable' "
    "|| steps.decide.outputs.decision == 'disarm' "
    "|| steps.decide.outputs.update_branch == 'true'"
)
DEFAULT_EXPR = "${{ github.token }}"
MINTED_EXPR = "${{ steps.mint.outputs.token }}"
DOCS_URL = (
    "https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/"
    "trigger-a-workflow#triggering-a-workflow-from-a-workflow"
)
DOCS_QUOTE = (
    "events triggered by the\n# GITHUB_TOKEN will not create a new workflow run, "
    "with the following exceptions"
)
TITLE_EXPR = "${{ github.event.pull_request.title }}"

_PINNED_USES_RE = re.compile(r"^\s*-?\s*uses:\s*\S+@[0-9a-f]{40}\s+#\s*v\d+\.\d+\.\d+\s*$")
_USES_LINE_RE = re.compile(r"^\s*-?\s*uses:")
# Pull-request payload fields an attacker controls as free text. Logins, numbers, flags and the
# repository name are not among them. The title is admitted in exactly one place (see the test).
_UNTRUSTED_FIELD_RE = re.compile(
    r"github\.event\.pull_request\.(title|body|head\.(ref|label|repo)|user\.(?!login\b)\w+)"
    r"|github\.head_ref|github\.event\.review\.body|github\.event\.comment"
)
_TOKEN_REF_RE = re.compile(
    r"(secrets\.\w+\b|github\.token\b|steps\.[\w-]+\.outputs\.token\b)(?!\s*(?:!=|==))"
)


def _triggers(doc: dict) -> dict:
    return doc.get("on") or doc[True]  # PyYAML 1.1 reads a bare `on:` key as boolean True


def _code_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]


def _find(steps: list[dict], **key: str) -> dict:
    ((field, value),) = key.items()
    found = [s for s in steps if s.get(field) == value]
    assert len(found) == 1, f"expected one step with {field}={value!r}, found {len(found)}"
    return found[0]


def _step(**key: str) -> dict:
    return _find(STEPS, **key)


def _sweep_step(**key: str) -> dict:
    return _find(SWEEP_STEPS, **key)


def _label(step: dict) -> str:
    return step.get("id") or step["name"]


def _token_keys(step: dict, mapping: str) -> list[str]:
    return sorted(k for k, v in (step.get(mapping) or {}).items() if _TOKEN_REF_RE.search(str(v)))


# --- the reusable workflow -------------------------------------------------------------------


def test_every_remote_action_is_pinned_to_a_sha_with_a_version_comment():
    raw = [ln for ln in _code_lines(TEXT) if _USES_LINE_RE.match(ln)]
    parsed = [s["uses"] for s in ALL_STEPS if "uses" in s]
    assert parsed and len(raw) == len(parsed), (raw, parsed)
    assert set(parsed) == {MINT_ACTION, METADATA_ACTION}
    for line in raw:
        assert _PINNED_USES_RE.match(line), f"not `@<40-hex sha> # vX.Y.Z`: {line.strip()}"


def test_nothing_from_the_pull_request_can_execute():
    """Secrets are present: no checkout of anything, no local action, no `${{ }}` inside a run
    body, and of the free-text pull-request fields only the title -- in the Decide step's
    environment, where it is matched against a grammar and never executed."""
    for step in ALL_STEPS:
        uses = step.get("uses", "")
        assert not uses.startswith("actions/checkout"), step
        assert not uses.startswith("./"), step
        assert "${{" not in (step.get("run") or ""), _label(step)
    code = "\n".join(_code_lines(TEXT))
    assert "checkout" not in code.lower()
    hits = [m.group(0) for m in _UNTRUSTED_FIELD_RE.finditer(code)]
    assert hits == ["github.event.pull_request.title"], hits
    decide = _step(id="decide")
    assert decide["env"]["PR_TITLE"] == TITLE_EXPR
    # and the title is the only free-text field any step's env carries
    for step in ALL_STEPS:
        for name, value in (step.get("env") or {}).items():
            if _UNTRUSTED_FIELD_RE.search(str(value)):
                assert (_label(step), name) == ("decide", "PR_TITLE"), (step, name)


def test_default_token_is_read_only_and_the_workflow_grants_nothing_at_top_level():
    assert DOC["permissions"] == {}
    assert set(JOBS) == {"enable", "sweep"}
    for job in (ENABLE, SWEEP):
        assert job["permissions"] == JOB_PERMISSIONS
        assert job["runs-on"] == "ubuntu-latest"
        assert job["timeout-minutes"] <= 5
        assert job["concurrency"]["cancel-in-progress"] is True
    # the two jobs split the events: a push runs the sweep and nothing else
    assert ENABLE["if"] == "github.event_name != 'push'"
    assert SWEEP["if"] == "github.event_name == 'push'"
    assert "github.event.pull_request.number" in ENABLE["concurrency"]["group"]
    assert SWEEP["concurrency"]["group"].endswith("-sweep")


def test_call_interface_defaults_keep_majors_open_and_take_exactly_one_secret():
    call = _triggers(DOC)["workflow_call"]
    inputs = call["inputs"]
    assert set(inputs) == {"auto_merge_majors", "merge_method", "reviewer", "app_id", "app_slug"}
    assert inputs["auto_merge_majors"]["type"] == "boolean"
    assert inputs["auto_merge_majors"]["default"] is False
    assert inputs["merge_method"]["type"] == "string"
    assert inputs["merge_method"]["default"] == "squash"
    assert inputs["reviewer"]["type"] == "string"
    assert inputs["reviewer"]["default"] == "codna-ai"
    assert inputs["app_id"]["type"] == "string"
    assert re.fullmatch(r"\d+", str(inputs["app_id"]["default"])), "the App id is a public number"
    assert inputs["app_slug"]["type"] == "string"
    assert inputs["app_slug"]["default"] == "algenta-sdk-sync"
    assert set(call["secrets"]) == {"app_private_key"}
    assert call["secrets"]["app_private_key"]["required"] is True


def test_metadata_is_read_only_for_dependabot_authored_pull_requests():
    metadata = _step(id="metadata")
    assert metadata["uses"] == METADATA_ACTION
    assert metadata["if"] == "github.event.pull_request.user.login == 'dependabot[bot]'"
    assert metadata["with"] == {"github-token": "${{ github.token }}"}


def test_facts_step_reads_reviews_and_threads_with_the_read_only_default_token():
    facts = _step(id="facts")
    assert _token_keys(facts, "env") == ["GH_TOKEN"]
    assert facts["env"]["GH_TOKEN"] == DEFAULT_EXPR
    run = facts["run"]
    # the setting is read through GraphQL (`autoMergeAllowed`), never REST: REST's
    # `allow_auto_merge` reads null to a read-only token, which v0.1.15 mistook for "off"
    assert "autoMergeAllowed" in run and ".data.repository.autoMergeAllowed" in run
    assert ".allow_auto_merge" not in run and 'gh api "repos/${GITHUB_REPOSITORY}"' not in run
    # a base branch with a merge queue is the queue's to update
    assert "pullRequest(number: $number) { isMergeQueueEnabled }" in run
    assert "autoMergeRequest.enabledBy.login" in run
    assert "reviewDecision" in run and "isCrossRepository" in run and "headRefOid" in run
    # the reviewer's LATEST review, matched with or without the [bot] suffix, and the commit it
    # was submitted against (the approval gate is head-bound); jq reads the login from the step's
    # environment, so the single-quoted program carries no shell-looking `$`
    assert "| last'" in run and '(env.REVIEWER + "[bot]")' in run and "--arg" not in run
    assert '"$latest | .state // empty"' in run and '"$latest | .commit.oid // empty"' in run
    assert facts["env"]["REVIEWER"] == "${{ inputs.reviewer }}"
    # mergeability is recomputed after a push and reads UNKNOWN meanwhile: the read is repeated
    assert "for attempt in 1 2 3 4; do" in run and "sleep 5" in run
    assert '"$(jq -r \'.mergeStateStatus\' <<<"$pr")" = "UNKNOWN"' in run
    # unresolved threads come from GraphQL, every page of them (codna finding on #16: a
    # first-page-only count over-counted past 100 threads); the check-run conclusion is never read
    assert "reviewThreads(first: 100, after: $endCursor)" in run and "isResolved" in run
    assert "--paginate --slurp" in run and "pageInfo { hasNextPage endCursor }" in run
    assert "totalCount" not in run
    # gh refuses `--slurp` together with `--jq` ("the `--slurp` option is not supported with
    # `--jq` or `--template`"); v0.1.14 shipped that combination and the step failed on the
    # first live event. The slurped array goes to jq itself, on the pipeline's next line.
    for command in re.split(r"\n(?!\s*\|)", run):
        if "gh api" in command and "--slurp" in command:
            head = command.split("|", 1)[0]
            assert "--jq" not in head, command
            assert re.search(r"\|\s*jq ", command), command
    assert "checks" not in run.lower() and "statusCheckRollup" not in run
    # read-only: no mutation, no merge, no thread resolution
    forbidden = ("gh pr merge", "-X PUT", "-X POST", "-X PATCH", "mutation", "resolveReviewThread")
    for word in forbidden:
        assert word not in run, word
    # every fact the Decide step consumes is written here
    written = set(re.findall(r'^\s*echo "([a-z_]+)=', run, re.M))
    consumed = {
        re.search(r"steps\.facts\.outputs\.(\w+)", v).group(1)
        for v in _step(id="decide")["env"].values()
        if "steps.facts.outputs." in v
    }
    assert consumed <= written, consumed - written


def test_mint_is_gated_on_acting_and_scoped_to_this_repository():
    for steps, gate in ((STEPS, ACTING), (SWEEP_STEPS, "steps.behind.outputs.count != '0'")):
        mint = _find(steps, id="mint")
        assert mint["uses"] == MINT_ACTION
        assert mint["if"] == gate
        with_ = mint["with"]
        assert with_["app-id"] == "${{ inputs.app_id }}"
        assert with_["private-key"] == "${{ secrets.app_private_key }}"
        assert with_["owner"] == "${{ github.repository_owner }}"
        assert with_["repositories"] == "${{ github.event.repository.name }}"
        granted = {k: v for k, v in with_.items() if k.startswith("permission-")}
        assert granted == TOKEN_PERMISSIONS, granted
        # the App that minted the token is the App whose auto-merge Decide recognised, or the
        # job stops before it touches anything
        check = _find(steps, name="The App inputs name one App")
        assert check["if"] == gate
        assert check["env"] == {
            "MINTED_SLUG": "${{ steps.mint.outputs.app-slug }}",
            "APP_SLUG": "${{ inputs.app_slug }}",
        }
        assert '[ "$MINTED_SLUG" != "$APP_SLUG" ]' in check["run"] and "exit 1" in check["run"]


def test_enable_uses_the_app_token_and_gh_pr_merge_auto():
    enable = _step(name="Enable auto-merge")
    assert enable["if"] == "steps.decide.outputs.decision == 'enable'"
    assert enable["env"]["GH_TOKEN"] == MINTED_EXPR
    run = enable["run"]
    assert re.search(
        r'gh pr merge "\$PR_NUMBER" -R "\$GITHUB_REPOSITORY" --auto "--\$\{MERGE_METHOD\}"', run
    )
    assert "--admin" not in run and "--delete-branch" not in run
    assert "resolveReviewThread" not in TEXT, "findings are never resolved by this workflow"
    assert "GITHUB_STEP_SUMMARY" in run and "::notice title=dependabot-auto-merge::" in run
    # the notice and the summary carry the effective type and how it was classified
    assert enable["env"]["UPDATE_TYPE"] == "${{ steps.decide.outputs.update_type }}"
    assert enable["env"]["BASIS"] == "${{ steps.decide.outputs.update_type_basis }}"


def test_disarm_disables_only_what_decide_attributed_to_this_app():
    disarm = _step(name="Disarm")
    assert disarm["if"] == "steps.decide.outputs.decision == 'disarm'"
    assert disarm["env"]["GH_TOKEN"] == MINTED_EXPR
    run = disarm["run"]
    assert 'gh pr merge "$PR_NUMBER" -R "$GITHUB_REPOSITORY" --disable-auto' in run
    assert "--auto " not in run and "--admin" not in run
    assert "disarmed: ${REASON}" in run and "GITHUB_STEP_SUMMARY" in run
    # Decide attributes an arm to this App by the login gh renders for a Bot, or the [bot] form
    script = _decide_script()
    assert '"app/${APP_SLUG}"|"${APP_SLUG}[bot]")' in script
    assert "a human's decision is never overridden" in script


def test_update_branch_merges_the_base_in_and_never_rebases():
    """The update goes through gh's update-branch (the `updatePullRequestBranch` mutation, guarded
    by the expected head, a no-op when not behind) with its default MERGE method: fetch-metadata
    verifies the pull request's first commit, which a merge leaves in place and a rebase rewrites
    into a commit GitHub does not sign. Dependabot's own `@dependabot rebase` is not an option:
    it refuses the command from a GitHub App (dependabot/dependabot-core#9147)."""
    update = _step(name="Bring the pull request up to date with its base branch")
    assert update["if"] == "steps.decide.outputs.update_branch == 'true'"
    assert update["env"]["GH_TOKEN"] == MINTED_EXPR
    run = update["run"]
    assert 'gh pr update-branch "$PR_NUMBER" -R "$GITHUB_REPOSITORY"' in run
    assert "--rebase" not in run
    for step in ALL_STEPS:
        body = step.get("run") or ""
        assert "@dependabot rebase" not in body, _label(step)
        assert "--rebase" not in body, _label(step)
        assert "updateMethod" not in body and "REBASE" not in body, _label(step)
    sweep_update = _sweep_step(name="Bring them up to date")
    assert sweep_update["if"] == "steps.behind.outputs.count != '0'"
    assert sweep_update["env"]["GH_TOKEN"] == MINTED_EXPR
    assert 'gh pr update-branch "$n" -R "$GITHUB_REPOSITORY"' in sweep_update["run"]
    # a failed update is reported and fails the job; the others are still attempted
    assert 'failed="${failed} #${n}"' in sweep_update["run"] and "exit 1" in sweep_update["run"]


def test_secret_values_reach_only_the_mint_actions_and_the_acting_steps():
    token_env = {_label(s): _token_keys(s, "env") for s in ALL_STEPS if _token_keys(s, "env")}
    assert token_env == {
        "facts": ["GH_TOKEN"],
        "Enable auto-merge": ["GH_TOKEN"],
        "Disarm": ["GH_TOKEN"],
        "Bring the pull request up to date with its base branch": ["GH_TOKEN"],
        "behind": ["GH_TOKEN"],
        "Bring them up to date": ["GH_TOKEN"],
    }, token_env
    # the read-only steps hold the default token, the acting steps the minted one, no step both
    for label in ("facts", "behind"):
        assert _find(ALL_STEPS, id=label)["env"]["GH_TOKEN"] == DEFAULT_EXPR
    for label in set(token_env) - {"facts", "behind"}:
        assert _find(ALL_STEPS, name=label)["env"]["GH_TOKEN"] == MINTED_EXPR
    token_with = {_label(s): _token_keys(s, "with") for s in ALL_STEPS if _token_keys(s, "with")}
    assert token_with == {"metadata": ["github-token"], "mint": ["private-key"]}, token_with
    assert sum(1 for s in ALL_STEPS if s.get("id") == "mint") == 2, "one mint per job"
    # cross-count against the raw text so no `secrets.*` reference hides outside env:/with:
    raw = sum(ln.count("secrets.") for ln in _code_lines(TEXT))
    parsed = sum(
        str(v).count("secrets.")
        for s in ALL_STEPS
        for mapping in ("env", "with")
        for v in (s.get(mapping) or {}).values()
    )
    assert raw == parsed == 2, (raw, parsed)
    # no run body echoes a token-holding variable
    for step in ALL_STEPS:
        for line in (step.get("run") or "").splitlines():
            if re.search(r"\b(echo|printf)\b", line):
                assert not re.search(r"\$\{?GH_TOKEN\b", line), (_label(step), line)


def test_header_states_the_design_and_cites_the_docs():
    header = TEXT.split("\nname:", 1)[0]
    assert DOCS_URL in header
    assert DOCS_QUOTE in header
    assert "workflow_dispatch and repository_dispatch" in header
    assert "codna" in header and "must not adopt" in header
    assert "triggering_actor=algenta-sdk-sync[bot]" in header
    # the two facts the review-keyed decision rests on
    assert "`neutral`" in header and "required_review_thread_resolution" in header
    assert "never on the `codna review` check-run" in header
    assert "Findings are never resolved here" in header
    assert "strict required status checks" in header and "BEHIND" in header
    # v0.1.17: the three facts behind the disarm, the classification and the branch update
    assert "An arm is good for one head" in header and "#150" in header
    assert "`<2,>=1.29.0`" in header and "#153" in header and "lower bounds" in header
    assert "dependabot/dependabot-core#9147" in header
    assert "only users with\n# push access can use that command" in header
    assert "updatePullRequestBranch" in header and "merge queue" in header
    assert "does not sign" in header, "why the update merges rather than rebases"


# --- the Decide step, run for real -------------------------------------------------------------


def _decide_script() -> str:
    return _step(id="decide")["run"]


def _run_decide(env_overrides: dict[str, str], tmp_path: Path) -> tuple[int, str, dict[str, str]]:
    out = tmp_path / "output.txt"
    out.write_text("")
    env = {
        "PATH": os.environ["PATH"],
        "GITHUB_OUTPUT": str(out),
        **CASES["baseline"],
        **env_overrides,
    }
    proc = subprocess.run(
        ["bash", "-c", _decide_script()], env=env, capture_output=True, text=True, check=False
    )
    return proc.returncode, proc.stdout + proc.stderr, _parse_github_output(out.read_text())


_HEREDOC_START_RE = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_-]*)<<(?P<delim>.+)$")
OUTPUTS = {"decision", "reason", "update_type", "update_type_basis", "update_branch"}


def _parse_github_output(text: str) -> dict[str, str]:
    """Read $GITHUB_OUTPUT the way the runner does: a line is the start of the multiline-safe
    form only when a bare output name is followed by `<<DELIM` (the runner's grammar; `=` is not
    a name character), and the value runs to the line equal to DELIM, newlines kept. Every other
    line is `name=value`."""
    outputs: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        start = _HEREDOC_START_RE.match(line)
        if start:
            key, delim = start.group("key"), start.group("delim")
            body: list[str] = []
            i += 1
            while i < len(lines) and lines[i] != delim:
                body.append(lines[i])
                i += 1
            assert i < len(lines), f"unterminated heredoc for {key!r} in GITHUB_OUTPUT"
            outputs[key] = "\n".join(body)
        else:
            key, _, value = line.partition("=")
            outputs[key] = value
        i += 1
    return outputs


@pytest.mark.parametrize("case", CASES["cases"], ids=[c["name"] for c in CASES["cases"]])
def test_decide(case: dict, tmp_path: Path):
    rc, combined, outputs = _run_decide(case["env"], tmp_path)
    expect = case["expect"]
    if "exit_code" in expect:
        assert rc == expect["exit_code"], combined
        assert expect["output_contains"] in combined, combined
        assert "::error title=dependabot-auto-merge::" in combined
        assert "decision" not in outputs, outputs
        return
    assert rc == 0, combined
    assert set(outputs) == OUTPUTS, outputs
    assert outputs["decision"] == expect["decision"], (outputs, combined)
    assert outputs["update_branch"] == expect.get("update_branch", "false"), outputs
    if "update_type" in expect:
        assert outputs["update_type"] == expect["update_type"], outputs
    raw = (tmp_path / "output.txt").read_text()
    # every output is written in the multiline-safe form (codna findings on #16), so a value
    # with a newline reaches the summary whole instead of becoming a second, bogus output --
    # and the delimiter is random per call, so no value can end the block early
    for name in OUTPUTS:
        start = re.search(rf"^{name}<<({name}_[0-9a-f]{{32}})$", raw, re.M)
        assert start, (name, raw)
        assert start.group(1) not in outputs[name], raw
        assert f"\n{name}=" not in raw and not raw.startswith(f"{name}="), raw
    if expect["decision"] in ("skip", "disarm"):
        assert expect["reason_contains"] in outputs["reason"], outputs
        assert "::notice title=dependabot-auto-merge::" in combined, combined
        assert outputs["reason"] in combined
        verb = "not enabling auto-merge" if expect["decision"] == "skip" else "disarming"
        assert f"#39: {verb} -- " in combined, combined
    else:
        assert outputs["reason"] == ""
        assert "::notice" not in combined and "::error" not in combined, combined
        assert outputs["update_type"].startswith("version-update:semver-"), outputs


def _literal_prefix(template: str) -> str:
    """The part of a `skip "..."` / `disarm "..."` / `refuse "..."` message before its first
    shell expansion."""
    return template.split("$", 1)[0]


def test_every_skip_disarm_and_refusal_in_the_script_is_reached_by_a_case(tmp_path: Path):
    """The lists come from the script; a new skip, disarm or refusal without a case fails here."""
    script = _decide_script()
    # `finish skip "$1"` / `finish disarm "$1"` inside the helpers are the helpers' own calls
    skips = [m for m in re.findall(r'\bskip "([^"]+)"', script) if m != "$1"]
    disarms = [m for m in re.findall(r'\bdisarm "([^"]+)"', script) if m != "$1"]
    refusals = re.findall(r'\brefuse "([^"]+)"', script)
    assert skips and disarms and refusals, "no skip/disarm/refuse reasons found in the Decide step"
    # every message has a literal, distinguishing prefix, so the check below means something
    for messages in (skips, disarms):
        prefixes = [_literal_prefix(m) for m in messages]
        assert all(prefixes), messages
    reached: dict[str, set[str]] = {"skip": set(), "disarm": set()}
    refusal_output = ""
    for case in CASES["cases"]:
        rc, combined, outputs = _run_decide(case["env"], tmp_path)
        if rc == 0 and outputs.get("decision") in reached:
            reached[outputs["decision"]].add(outputs["reason"])
        elif rc != 0:
            refusal_output += combined
    for decision, messages in (("skip", skips), ("disarm", disarms)):
        unreached = [
            m
            for m in messages
            if not any(got.startswith(_literal_prefix(m)) for got in reached[decision])
        ]
        assert not unreached, (decision, unreached)
    unreached = [r for r in refusals if _literal_prefix(r) not in refusal_output]
    assert not unreached, unreached
    # and every case name is unique, so a failure names one case
    names = [c["name"] for c in CASES["cases"]]
    assert len(names) == len(set(names))


def test_baseline_case_is_the_eligible_approved_dependabot_minor_update():
    base = CASES["baseline"]
    assert base["EVENT_NAME"] == "pull_request_target" and base["EVENT_ACTION"] == "opened"
    assert base["PR_AUTHOR"] == base["ACTOR"] == "dependabot[bot]"
    assert base["UPDATE_TYPE"] == "version-update:semver-minor"
    assert base["PR_TITLE"].startswith("chore(deps): bump "), "a version bump, not a range update"
    assert base["AUTO_MERGE_MAJORS"] == "false" and base["AUTO_MERGE_ENABLED_BY"] == ""
    assert base["REVIEWER_REVIEW"] == "APPROVED" and base["UNRESOLVED_THREADS"] == "0"
    assert base["REVIEWER_REVIEW_COMMIT"] == base["HEAD_SHA"], "codna approved the current head"
    assert base["MERGE_STATE"] == "CLEAN" and base["MERGE_QUEUE"] == "false"
    # every variable the script reads is set by the baseline, so no case depends on the host env
    read = set(re.findall(r"\$\{?([A-Z_]+)\b", _decide_script())) - {
        "GITHUB_OUTPUT",
        "BASH_REMATCH",
    }
    assert read <= set(base), read - set(base)
    # and the baseline is what the Decide step's env: feeds, name for name
    fed = {re.sub(r"[^A-Z_]", "", k) for k in _step(id="decide")["env"]}
    assert fed == set(base), fed ^ set(base)


def test_the_review_gate_is_the_reviewers_latest_review_of_this_head_not_the_check_run(
    tmp_path: Path,
):
    """Coordinator fact, 2026-09-20: codna's check-run concludes neutral with any inline finding
    and success only when finding-free; neutral passes a required check. So the decision keys on
    the review state, the commit the review was submitted against and the unresolved-thread
    count, and it never resolves a thread."""
    script = _decide_script()
    assert "REVIEWER_REVIEW" in script and "UNRESOLVED_THREADS" in script
    assert "REVIEWER_REVIEW_COMMIT" in script and "HEAD_SHA" in script
    assert "conclusion" not in script and "SUCCESS" not in script
    for review in ("COMMENTED", "CHANGES_REQUESTED", "DISMISSED", "PENDING", ""):
        rc, _, outputs = _run_decide({"REVIEWER_REVIEW": review}, tmp_path)
        assert rc == 0 and outputs["decision"] == "skip", (review, outputs)
    for threads in ("1", "2", "100"):
        rc, _, outputs = _run_decide({"UNRESOLVED_THREADS": threads}, tmp_path)
        assert rc == 0 and outputs["decision"] == "skip", (threads, outputs)
    for commit in ("", "b" * 40, "a" * 39):
        rc, _, outputs = _run_decide({"REVIEWER_REVIEW_COMMIT": commit}, tmp_path)
        assert rc == 0 and outputs["decision"] == "skip", (commit, outputs)
        assert "approved at" in outputs["reason"], outputs


def test_an_arm_is_good_for_one_head(tmp_path: Path):
    """algenta-integrations #150: armed on head A, Dependabot rebased to B, the approval was
    carried, codna then posted a finding on B, and the pull request would have merged the moment
    the checks passed. The App's own arm is disarmed on a new head and on any codna verdict that
    is not an approval of the current head; a human's arm is never touched."""
    ours = {"AUTO_MERGE_ENABLED_BY": "app/algenta-sdk-sync"}
    new_head = {**ours, "EVENT_ACTION": "synchronize"}
    for actor in ("dependabot[bot]", "0xamlab", "algenta-sdk-sync[bot]"):
        rc, _, outputs = _run_decide({**new_head, "ACTOR": actor}, tmp_path)
        assert rc == 0 and outputs["decision"] == "disarm", (actor, outputs)
        assert outputs["update_branch"] == "false", outputs
    for verdict in (
        {"REVIEWER_REVIEW": "COMMENTED"},
        {"REVIEWER_REVIEW": "CHANGES_REQUESTED"},
        {"REVIEWER_REVIEW": "DISMISSED"},
        {"REVIEWER_REVIEW": ""},
        {"REVIEWER_REVIEW_COMMIT": "b" * 40},
        {"REVIEWER_REVIEW_COMMIT": ""},
        {"UNRESOLVED_THREADS": "1"},
    ):
        rc, _, outputs = _run_decide({**ours, **verdict}, tmp_path)
        assert rc == 0 and outputs["decision"] == "disarm", (verdict, outputs)
        theirs = {**verdict, "AUTO_MERGE_ENABLED_BY": "0xamlab"}
        rc, _, outputs = _run_decide(theirs, tmp_path)
        assert rc == 0 and outputs["decision"] == "skip", (verdict, outputs)
        assert "already enabled, by 0xamlab" in outputs["reason"], outputs
    # holding conditions: no disarm, and a BEHIND branch is brought up to date
    rc, _, outputs = _run_decide(ours, tmp_path)
    assert rc == 0 and outputs["decision"] == "skip" and outputs["update_branch"] == "false"
    rc, _, outputs = _run_decide({**ours, "MERGE_STATE": "BEHIND"}, tmp_path)
    assert rc == 0 and outputs["decision"] == "skip" and outputs["update_branch"] == "true"


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("<2,>=1.29.0", ">=1.30.0,<2", "version-update:semver-minor"),  # #153
        (">=1.29.0,<2", ">=1.29.1,<2", "version-update:semver-patch"),
        (">=1.29.0,<2", ">=2.0.0,<3", None),  # the upper bound moved too
        (">=68.0", ">=84.0.0", "version-update:semver-major"),  # #147
        ("<4,>=3", ">=3.4.7,<4", "version-update:semver-minor"),  # #151
        (">=0.27", ">=0.28.1", "version-update:semver-minor"),  # #152
        (">=0.34", ">=0.52.4", "version-update:semver-minor"),  # #154
        ("~=1.4", "~=1.4.2", "version-update:semver-patch"),
        ("==2024.1", "==2025.1", "version-update:semver-major"),
        (">=1.0,<2,!=1.3", ">=1.4,<2,!=1.3", "version-update:semver-minor"),
        (">=1.0,<2,!=1.3", ">=1.4,!=1.3,<2", "version-update:semver-minor"),  # order-free
        (">=1.0,<2", ">=1.4", None),  # the upper bound dropped
        (">=1.0", ">=1.4,<2", None),  # an upper bound added
        (">=1.0,>=1.1", ">=1.4", None),  # two lower bounds
        (">=1.0rc1", ">=1.0", None),  # not all-numeric
        (">=1.*", ">=2", None),  # wildcard
        ("<2", "<3", None),  # no lower bound
        (">=v1.0", ">=v1.1", None),  # a leading v is not pip
    ],
)
def test_requirement_update_classification(old: str, new: str, expected: str | None, tmp_path):
    env = {"PR_TITLE": f"Update pkg requirement from {old} to {new}", "UPDATE_TYPE": ""}
    rc, _, outputs = _run_decide(env, tmp_path)
    assert rc == 0, outputs
    if expected is None:
        assert outputs["decision"] == "skip" and outputs["update_type"] == "", outputs
        assert "a human decides" in outputs["reason"], outputs
    else:
        assert outputs["update_type"] == expected, outputs
        assert outputs["update_type_basis"].startswith("derived from the lower bounds"), outputs
        assert f"{old} -> {new}" in outputs["update_type_basis"], outputs
        want = "skip" if expected.endswith("major") else "enable"
        assert outputs["decision"] == want, outputs


def test_fetch_metadata_type_is_overridden_only_for_a_requirement_update(tmp_path: Path):
    """The misread: fetch-metadata strips only the first specifier's operator from the old range,
    so `<2,>=1.29.0` becomes version `2,>=1.29.0` and a floor bump reads as a major. The title
    decides for the requirement form; fetch-metadata's type stands for every other title."""
    title = "chore(maf-algenta): Update mcp requirement from <2,>=1.29.0 to >=1.30.0,<2 in /x"
    for reported in ("version-update:semver-major", "version-update:semver-minor", "", "junk"):
        rc, _, outputs = _run_decide({"PR_TITLE": title, "UPDATE_TYPE": reported}, tmp_path)
        assert rc == 0 and outputs["decision"] == "enable", (reported, outputs)
        assert outputs["update_type"] == "version-update:semver-minor", outputs
        noted = reported not in ("", "version-update:semver-minor")
        assert ("dependabot/fetch-metadata reported" in outputs["update_type_basis"]) == noted
    for title in ("Bump mcp from 1.29.0 to 2.0.0", "Bump the pip group with 2 updates"):
        rc, _, outputs = _run_decide(
            {"PR_TITLE": title, "UPDATE_TYPE": "version-update:semver-major"}, tmp_path
        )
        assert rc == 0 and outputs["decision"] == "skip", (title, outputs)
        assert outputs["update_type"] == "version-update:semver-major", outputs
        assert outputs["update_type_basis"] == "reported by dependabot/fetch-metadata", outputs


def test_the_title_is_matched_never_executed_and_echoed_only_as_range_tokens(tmp_path: Path):
    marker = tmp_path / "executed"
    for title in (
        f"Update x requirement from $(touch {marker}) to >=1",
        f"Update x requirement from `touch {marker}` to >=1",
        f"Update x requirement from >=1;touch {marker} to >=2",
        f"$(touch {marker})",
        "::set-output name=decision::enable",
        "Update x requirement from ::error::boom to >=1",
    ):
        rc, combined, outputs = _run_decide({"PR_TITLE": title}, tmp_path)
        assert rc == 0, (title, combined)
        assert not marker.exists(), title
        assert "touch" not in combined and "touch" not in json.dumps(outputs), (title, combined)
        assert "set-output" not in combined, combined
        assert "::error" not in combined, combined
        assert outputs["decision"] in ("skip", "enable"), outputs
    # a range token is echoed as is; anything else as `(unprintable)`
    title = "Update x requirement from <2 to >=1.30.0,<2"
    rc, _, outputs = _run_decide({"PR_TITLE": title}, tmp_path)
    assert "<2 -> >=1.30.0,<2" in outputs["reason"], outputs
    rc, _, outputs = _run_decide({"PR_TITLE": "Update x requirement from <2 to $(id)"}, tmp_path)
    assert "<2 -> (unprintable)" in outputs["reason"], outputs


# --- the sweep job's selection, run for real ---------------------------------------------------


def _sweep_filter() -> str:
    run = _sweep_step(id="behind")["run"]
    m = re.search(r"^\s*filter='(?P<jq>.*?)'\n", run, re.S | re.M)
    assert m, run
    return m.group("jq")


def _node(**over) -> dict:
    node = {
        "number": 1,
        "isDraft": False,
        "isCrossRepository": False,
        "isMergeQueueEnabled": False,
        "mergeStateStatus": "BEHIND",
        "headRefOid": "a" * 40,
        "author": {"login": "dependabot", "__typename": "Bot"},
        "autoMergeRequest": {"enabledBy": {"login": "algenta-sdk-sync", "__typename": "Bot"}},
    }
    node.update(over)
    return node


def test_sweep_selects_only_this_apps_armed_dependabot_pull_requests():
    nodes = [
        _node(number=1),
        _node(number=2, mergeStateStatus="UNKNOWN"),
        _node(number=3, mergeStateStatus="CLEAN"),
        _node(number=4, autoMergeRequest=None),
        _node(number=5, autoMergeRequest={"enabledBy": {"login": "0xamlab", "__typename": "User"}}),
        _node(number=6, autoMergeRequest={"enabledBy": {"login": "renovate", "__typename": "Bot"}}),
        # a human whose login is the App's slug is not the App
        _node(
            number=7,
            autoMergeRequest={"enabledBy": {"login": "algenta-sdk-sync", "__typename": "User"}},
        ),
        _node(number=8, author={"login": "0xamlab", "__typename": "User"}),
        _node(number=9, author={"login": "renovate", "__typename": "Bot"}),
        _node(number=10, isDraft=True),
        _node(number=11, isCrossRepository=True),
        _node(number=12, isMergeQueueEnabled=True),
    ]
    pages = [
        {"data": {"repository": {"pullRequests": {"nodes": nodes[:6]}}}},
        {"data": {"repository": {"pullRequests": {"nodes": nodes[6:]}}}},
    ]
    # the slug reaches jq through the step's environment (`env.APP_SLUG`), never as `--arg`
    assert "env.APP_SLUG" in _sweep_filter() and "--arg" not in _sweep_step(id="behind")["run"]
    proc = subprocess.run(
        ["jq", "-c", _sweep_filter()],
        input=json.dumps(pages),
        env={"PATH": os.environ["PATH"], "APP_SLUG": "algenta-sdk-sync"},
        capture_output=True,
        text=True,
        check=True,
    )
    armed = json.loads(proc.stdout)
    # armed by this App, whatever the merge state: the step re-reads while any is UNKNOWN,
    # then acts on the BEHIND ones only
    assert [n["number"] for n in armed] == [1, 2, 3]
    run = _sweep_step(id="behind")["run"]
    assert 'select(.mergeStateStatus == "UNKNOWN")' in run and "sleep 10" in run
    assert 'select(.mergeStateStatus == "BEHIND")' in run
    assert "pullRequests(first: 100, states: OPEN, baseRefName: $base, after: $endCursor)" in run
    assert "--paginate --slurp" in run
    assert _sweep_step(id="behind")["env"]["BASE"] == "${{ github.ref_name }}"


# --- the caller template ----------------------------------------------------------------------


def _render(majors: str = "false", sha: str = SHA, tag: str = "v9.9.9") -> str:
    return TEMPLATE.read_text(encoding="utf-8").format(sha=sha, tag=tag, auto_merge_majors=majors)


@pytest.mark.parametrize("majors", ["false", "true"])
def test_template_renders_the_fleet_caller(majors: str):
    text = _render(majors)
    doc = yaml.safe_load(text)
    assert _triggers(doc) == CALLER_TRIGGERS
    assert doc["permissions"] == {}
    (job,) = doc["jobs"].values()
    # the pull request's author, which both pull-request events carry, and -- codna findings on
    # the rendered callers (telys#143, codna#575): any account can review a public repository's
    # pull request -- a review event only when it is the reviewing App's; the callee decides what
    # the review's state means. A push (to main: every fleet repository's default branch) runs
    # the callee's sweep.
    assert job["if"] == CALLER_IF, job["if"]
    assert job["uses"] == (
        f"thyn-ai/security-toolchain/.github/workflows/dependabot-auto-merge.yml@{SHA}"
    )
    assert job["permissions"] == JOB_PERMISSIONS
    assert job["with"] == {"auto_merge_majors": majors == "true"}
    assert job["secrets"] == {"app_private_key": "${{ secrets.ALGENTA_SDK_SYNC_APP_PRIVATE_KEY }}"}
    # the pin is what verify-toolchain reads
    assert verify.caller_pins(text) == [("dependabot-auto-merge.yml", SHA, "v9.9.9")]
    # the caller's job grants no less than the callee's jobs request
    for callee in (ENABLE, SWEEP):
        assert all(job["permissions"].get(k) == v for k, v in callee["permissions"].items())
    # the pull-request events the caller sends are exactly the ones the Decide step accepts, and
    # the push is the sweep's
    accepted = re.search(r"^\s*([a-z_|]+)\)\s*;;\s*$", _decide_script(), re.M).group(1).split("|")
    assert set(CALLER_TRIGGERS) - {"push"} == set(accepted), (CALLER_TRIGGERS.keys(), accepted)
    # and the pinned actionlint knows each of them (pull_request_review_thread, it does not:
    # the fleet's pre-commit hook lints every caller, so that trigger is out)
    assert "pull_request_review_thread" not in text


def test_template_documents_the_codna_review_precondition_and_the_app_attribution():
    header = TEMPLATE.read_text(encoding="utf-8").split("\nname:", 1)[0]
    assert "`codna review`" in header and "ONLY" in header
    assert "Codna Review required" in header
    assert "algenta-sdk-sync" in header and "GITHUB_TOKEN" in header
    assert "never checks out" in header
    assert "unresolved finding" in header
    assert "only\n# Dependabot and codna can start" in header
    assert "an arm is good for one\n# head" in header
    assert "never touched" in header, "a human's auto-merge"
    assert "push to `main`" in header and "BEHIND" in header


def test_a_review_event_reaches_the_job_only_from_the_reviewer(tmp_path: Path):
    """codna on the rendered callers: the `pull_request_review` trigger fires for every review by
    anyone, and any account can review a public repository's pull request. The caller's `if:`
    admits only the reviewing App's reviews; the Decide step refuses everyone else's too, so a
    caller without the filter gets the same answer. Since v0.1.17 the reviewer's non-approvals
    reach the job as well: on an unarmed pull request they are skipped, on one this App armed
    they disarm it."""
    script = _decide_script()
    assert "REVIEW_AUTHOR" in script and "REVIEW_STATE" in script
    review = {"EVENT_NAME": "pull_request_review", "EVENT_ACTION": "submitted", "ACTOR": "x"}
    for author, state in (
        ("stranger", "approved"),
        ("0xamlab", "approved"),
        ("codna-ai[bot]", "commented"),
        ("codna-ai[bot]", "changes_requested"),
        ("codna-ai", "dismissed"),
        ("", ""),
    ):
        rc, _, outputs = _run_decide(
            {**review, "REVIEW_AUTHOR": author, "REVIEW_STATE": state}, tmp_path
        )
        assert rc == 0 and outputs["decision"] == "skip", (author, state, outputs)
    for author in ("codna-ai[bot]", "codna-ai"):
        rc, _, outputs = _run_decide(
            {**review, "REVIEW_AUTHOR": author, "REVIEW_STATE": "approved"}, tmp_path
        )
        assert rc == 0 and outputs["decision"] == "enable", (author, outputs)
    # the caller's filter names the same reviewer the callee defaults to, and no state
    reviewer = _triggers(DOC)["workflow_call"]["inputs"]["reviewer"]["default"]
    assert f"github.event.review.user.login == '{reviewer}[bot]'" in CALLER_IF
    assert "review.state" not in CALLER_IF


def test_template_secret_name_is_the_org_wide_key_and_nothing_else_is_passed():
    text = _render()
    assert sum(ln.count("secrets.") for ln in _code_lines(text)) == 1
    assert "ALGENTA_SDK_SYNC_APP_PRIVATE_KEY" in text
    assert "ALGENTA_SDK_SYNC_APP_ID" not in text, "the App id is a public input, not a secret"
    assert "inherit" not in text
    # the App slug is the callee's default; a caller that changes app_id must pass app_slug too
    assert "app_slug" not in text and "app_id" not in text
