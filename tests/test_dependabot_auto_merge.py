"""dependabot-auto-merge.yml: Dependabot pull requests land on their own -- and safely.

The reusable workflow runs on `pull_request_target` (and the two review events) with the
repository's secrets, so the shape held here is a trust boundary: nothing from the pull request
may execute (no checkout, no local action, no pull-request free-text in a shell), the App's
private key reaches exactly one action input, the minted token exactly one step's environment,
the default token stays read-only, every remote action is SHA-pinned, and the merge is enabled
with the App token rather than GITHUB_TOKEN for the reason the header comment cites from GitHub's
docs.

The Decide step is a pure function of its environment. It is run here, under bash, against the
cases in tests/data/dependabot_auto_merge_cases.json: an approved, thread-free, minor or patch
update is enabled; everything the workflow promises to skip is skipped with a notice (majors,
unclassified changes, no or non-APPROVED codna review, unresolved threads, drafts, forks, a
human's existing auto-merge); a miscalled workflow is an error. Every `skip "..."` and
`refuse "..."` in the script must be reached by at least one case -- the lists of reasons are
read from the script, not counted.

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
(JOB,) = DOC["jobs"].values()
STEPS = JOB["steps"]

SHA = "c" * 40
MINT_ACTION = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
METADATA_ACTION = "dependabot/fetch-metadata@25dd0e34f4fe68f24cc83900b1fe3fe149efef98"
TOKEN_PERMISSIONS = {
    "permission-contents": "write",
    "permission-pull-requests": "write",
    "permission-workflows": "write",
    "permission-metadata": "read",
}
CALLER_TRIGGERS = {
    "pull_request_target": {"types": ["opened", "synchronize", "reopened"]},
    "pull_request_review": {"types": ["submitted"]},
}
DOCS_URL = (
    "https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/"
    "trigger-a-workflow#triggering-a-workflow-from-a-workflow"
)
DOCS_QUOTE = (
    "events triggered by the\n# GITHUB_TOKEN will not create a new workflow run, "
    "with the following exceptions"
)

_PINNED_USES_RE = re.compile(r"^\s*-?\s*uses:\s*\S+@[0-9a-f]{40}\s+#\s*v\d+\.\d+\.\d+\s*$")
_USES_LINE_RE = re.compile(r"^\s*-?\s*uses:")
# Pull-request payload fields an attacker controls as free text. Logins, numbers, flags and the
# repository name are not among them.
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


def _step(**key: str) -> dict:
    ((field, value),) = key.items()
    found = [s for s in STEPS if s.get(field) == value]
    assert len(found) == 1, f"expected one step with {field}={value!r}, found {len(found)}"
    return found[0]


def _label(step: dict) -> str:
    return step.get("id") or step["name"]


def _token_keys(step: dict, mapping: str) -> list[str]:
    return sorted(k for k, v in (step.get(mapping) or {}).items() if _TOKEN_REF_RE.search(str(v)))


# --- the reusable workflow -------------------------------------------------------------------


def test_every_remote_action_is_pinned_to_a_sha_with_a_version_comment():
    raw = [ln for ln in _code_lines(TEXT) if _USES_LINE_RE.match(ln)]
    parsed = [s["uses"] for s in STEPS if "uses" in s]
    assert parsed and len(raw) == len(parsed), (raw, parsed)
    assert set(parsed) == {MINT_ACTION, METADATA_ACTION}
    for line in raw:
        assert _PINNED_USES_RE.match(line), f"not `@<40-hex sha> # vX.Y.Z`: {line.strip()}"


def test_nothing_from_the_pull_request_can_execute():
    """Secrets are present: no checkout of anything, no local action, and none of the free-text
    pull-request fields anywhere in the file."""
    for step in STEPS:
        uses = step.get("uses", "")
        assert not uses.startswith("actions/checkout"), step
        assert not uses.startswith("./"), step
    code = "\n".join(_code_lines(TEXT))
    assert "checkout" not in code.lower()
    hit = _UNTRUSTED_FIELD_RE.search(code)
    assert not hit, hit.group(0)
    # no `${{ }}` inside a run body: values reach shells through env only
    for step in STEPS:
        assert "${{" not in (step.get("run") or ""), _label(step)


def test_default_token_is_read_only_and_the_workflow_grants_nothing_at_top_level():
    assert DOC["permissions"] == {}
    assert JOB["permissions"] == {"contents": "read", "pull-requests": "read"}
    assert JOB["runs-on"] == "ubuntu-latest"
    assert JOB["timeout-minutes"] <= 5
    assert JOB["concurrency"]["cancel-in-progress"] is True
    assert "github.event.pull_request.number" in JOB["concurrency"]["group"]


def test_call_interface_defaults_keep_majors_open_and_take_exactly_one_secret():
    call = _triggers(DOC)["workflow_call"]
    inputs = call["inputs"]
    assert set(inputs) == {"auto_merge_majors", "merge_method", "reviewer", "app_id"}
    assert inputs["auto_merge_majors"]["type"] == "boolean"
    assert inputs["auto_merge_majors"]["default"] is False
    assert inputs["merge_method"]["type"] == "string"
    assert inputs["merge_method"]["default"] == "squash"
    assert inputs["reviewer"]["type"] == "string"
    assert inputs["reviewer"]["default"] == "codna-ai"
    assert inputs["app_id"]["type"] == "string"
    assert re.fullmatch(r"\d+", str(inputs["app_id"]["default"])), "the App id is a public number"
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
    default_expr = "${{ github.token }}"
    assert facts["env"]["GH_TOKEN"] == default_expr
    run = facts["run"]
    assert "allow_auto_merge" in run and "autoMergeRequest.enabledBy.login" in run
    assert "reviewDecision" in run and "isCrossRepository" in run
    # the reviewer's LATEST review, matched with or without the [bot] suffix
    assert "| last | .state" in run and '($r + "[bot]")' in run
    # unresolved threads come from GraphQL, every page of them (codna finding on #16: a
    # first-page-only count over-counted past 100 threads); the check-run conclusion is never read
    assert "reviewThreads(first: 100, after: $endCursor)" in run and "isResolved" in run
    assert "--paginate --slurp" in run and "pageInfo { hasNextPage endCursor }" in run
    assert "totalCount" not in run
    assert "checks" not in run.lower() and "statusCheckRollup" not in run
    # read-only: no mutation, no merge, no thread resolution
    forbidden = ("gh pr merge", "-X PUT", "-X POST", "-X PATCH", "mutation", "resolveReviewThread")
    for word in forbidden:
        assert word not in run, word


def test_mint_is_gated_on_the_decision_and_scoped_to_this_repository():
    mint = _step(id="mint")
    assert mint["uses"] == MINT_ACTION
    assert mint["if"] == "steps.decide.outputs.decision == 'enable'"
    with_ = mint["with"]
    assert with_["app-id"] == "${{ inputs.app_id }}"
    assert with_["private-key"] == "${{ secrets.app_private_key }}"
    assert with_["owner"] == "${{ github.repository_owner }}"
    assert with_["repositories"] == "${{ github.event.repository.name }}"
    granted = {k: v for k, v in with_.items() if k.startswith("permission-")}
    assert granted == TOKEN_PERMISSIONS, granted


def test_enable_uses_the_app_token_and_gh_pr_merge_auto():
    enable = _step(name="Enable auto-merge")
    assert enable["if"] == "steps.decide.outputs.decision == 'enable'"
    minted_expr = "${{ steps.mint.outputs.token }}"
    assert enable["env"]["GH_TOKEN"] == minted_expr
    run = enable["run"]
    assert re.search(
        r'gh pr merge "\$PR_NUMBER" -R "\$GITHUB_REPOSITORY" --auto "--\$\{MERGE_METHOD\}"', run
    )
    assert "--admin" not in run and "--delete-branch" not in run
    assert "resolveReviewThread" not in TEXT, "findings are never resolved by this workflow"
    assert "GITHUB_STEP_SUMMARY" in run and "::notice title=dependabot-auto-merge::" in run


def test_secret_values_reach_only_the_mint_action_and_the_enable_step():
    token_env = {_label(s): _token_keys(s, "env") for s in STEPS if _token_keys(s, "env")}
    assert token_env == {"facts": ["GH_TOKEN"], "Enable auto-merge": ["GH_TOKEN"]}, token_env
    token_with = {_label(s): _token_keys(s, "with") for s in STEPS if _token_keys(s, "with")}
    assert token_with == {"metadata": ["github-token"], "mint": ["private-key"]}, token_with
    # cross-count against the raw text so no `secrets.*` reference hides outside env:/with:
    raw = sum(ln.count("secrets.") for ln in _code_lines(TEXT))
    parsed = sum(
        str(v).count("secrets.")
        for s in STEPS
        for mapping in ("env", "with")
        for v in (s.get(mapping) or {}).values()
    )
    assert raw == parsed == 1, (raw, parsed)
    # no run body echoes a token-holding variable
    for step in STEPS:
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


def _parse_github_output(text: str) -> dict[str, str]:
    """Read $GITHUB_OUTPUT the way the runner does: `name=value` lines, and the multiline-safe
    `name<<DELIM` ... `DELIM` form, whose value keeps its newlines."""
    outputs: dict[str, str] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "<<" in line and "=" not in line.split("<<", 1)[0]:
            key, delim = line.split("<<", 1)
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
    assert outputs["decision"] == expect["decision"], (outputs, combined)
    if expect["decision"] == "skip":
        assert expect["reason_contains"] in outputs["reason"], outputs
        assert "::notice title=dependabot-auto-merge::" in combined, combined
        assert outputs["reason"] in combined
        # the reason is written in the multiline-safe form (codna finding on #16), so a value
        # with a newline reaches the summary whole instead of becoming a second, bogus output
        raw = (tmp_path / "output.txt").read_text()
        assert "reason<<_REASON_\n" in raw and "\nreason=" not in raw, raw
        assert set(outputs) == {"decision", "reason"}, outputs
    else:
        assert outputs["reason"] == ""
        assert "::notice" not in combined and "::error" not in combined, combined


def _literal_prefix(template: str) -> str:
    """The part of a `skip "..."` / `refuse "..."` message before its first shell expansion."""
    return template.split("$", 1)[0]


def test_every_skip_and_refusal_in_the_script_is_reached_by_a_case(tmp_path: Path):
    """The lists come from the script; a new skip or refusal without a case fails here."""
    script = _decide_script()
    skips = re.findall(r'\bskip "([^"]+)"', script)
    refusals = re.findall(r'\brefuse "([^"]+)"', script)
    assert skips and refusals, "no skip/refuse reasons found in the Decide step"
    reached_skips: set[str] = set()
    refusal_output = ""
    for case in CASES["cases"]:
        rc, combined, outputs = _run_decide(case["env"], tmp_path)
        if rc == 0 and outputs.get("decision") == "skip":
            reached_skips.add(outputs["reason"])
        elif rc != 0:
            refusal_output += combined
    unreached = [
        s for s in skips if not any(got.startswith(_literal_prefix(s)) for got in reached_skips)
    ]
    assert not unreached, unreached
    unreached = [r for r in refusals if _literal_prefix(r) not in refusal_output]
    assert not unreached, unreached
    # and every case name is unique, so a failure names one case
    names = [c["name"] for c in CASES["cases"]]
    assert len(names) == len(set(names))


def test_baseline_case_is_the_eligible_approved_dependabot_minor_update():
    base = CASES["baseline"]
    assert base["EVENT_NAME"] == "pull_request_target"
    assert base["PR_AUTHOR"] == base["ACTOR"] == "dependabot[bot]"
    assert base["UPDATE_TYPE"] == "version-update:semver-minor"
    assert base["AUTO_MERGE_MAJORS"] == "false" and base["AUTO_MERGE_ENABLED_BY"] == ""
    assert base["REVIEWER_REVIEW"] == "APPROVED" and base["UNRESOLVED_THREADS"] == "0"
    # every variable the script reads is set by the baseline, so no case depends on the host env
    read = set(re.findall(r"\$\{?([A-Z_]+)\b", _decide_script())) - {"GITHUB_OUTPUT"}
    assert read <= set(base), read - set(base)
    # and the baseline is what the Decide step's env: feeds, name for name
    fed = {re.sub(r"[^A-Z_]", "", k) for k in _step(id="decide")["env"]}
    assert fed == set(base), fed ^ set(base)


def test_the_review_gate_is_the_reviewers_latest_review_not_the_check_run(tmp_path: Path):
    """Coordinator fact, 2026-09-20: codna's check-run concludes neutral with any inline finding
    and success only when finding-free; neutral passes a required check. So the decision keys on
    the review state and the unresolved-thread count, and it never resolves a thread."""
    script = _decide_script()
    assert "REVIEWER_REVIEW" in script and "UNRESOLVED_THREADS" in script
    assert "conclusion" not in script and "SUCCESS" not in script
    for review in ("COMMENTED", "CHANGES_REQUESTED", "DISMISSED", "PENDING", ""):
        rc, _, outputs = _run_decide({"REVIEWER_REVIEW": review}, tmp_path)
        assert rc == 0 and outputs["decision"] == "skip", (review, outputs)
    for threads in ("1", "2", "100"):
        rc, _, outputs = _run_decide({"UNRESOLVED_THREADS": threads}, tmp_path)
        assert rc == 0 and outputs["decision"] == "skip", (threads, outputs)


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
    # the pull request's author, which all three events carry; the callee checks the actor
    assert job["if"] == "github.event.pull_request.user.login == 'dependabot[bot]'"
    assert job["uses"] == (
        f"thyn-ai/security-toolchain/.github/workflows/dependabot-auto-merge.yml@{SHA}"
    )
    assert job["permissions"] == {"contents": "read", "pull-requests": "read"}
    assert job["with"] == {"auto_merge_majors": majors == "true"}
    assert job["secrets"] == {"app_private_key": "${{ secrets.ALGENTA_SDK_SYNC_APP_PRIVATE_KEY }}"}
    # the pin is what verify-toolchain reads
    assert verify.caller_pins(text) == [("dependabot-auto-merge.yml", SHA, "v9.9.9")]
    # the caller's job grants no less than the callee's job requests
    assert all(job["permissions"].get(k) == v for k, v in JOB["permissions"].items())
    # the events the caller sends are exactly the ones the Decide step accepts
    accepted = re.search(r"^\s*([a-z_|]+)\)\s*;;\s*$", _decide_script(), re.M).group(1).split("|")
    assert set(CALLER_TRIGGERS) == set(accepted), (CALLER_TRIGGERS.keys(), accepted)
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


def test_template_secret_name_is_the_org_wide_key_and_nothing_else_is_passed():
    text = _render()
    assert sum(ln.count("secrets.") for ln in _code_lines(text)) == 1
    assert "ALGENTA_SDK_SYNC_APP_PRIVATE_KEY" in text
    assert "ALGENTA_SDK_SYNC_APP_ID" not in text, "the App id is a public input, not a secret"
    assert "inherit" not in text
