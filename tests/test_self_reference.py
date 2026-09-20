"""The reusable workflows install the toolchain from their own commit -- by construction.

History, because it is why this file exists. security-full.yml and security-smoke.yml used to
install thyn-ai/security-toolchain through an internal `uses: thyn-ai/security-toolchain@vX.Y.Z`
step: a literal that no expression can make dynamic, which sat at "v0.1.1" through five
releases because nothing checked it. A test then held that literal equal to `__version__`,
but a tag is only a name (OpenSSF Scorecard reads it as an unpinned dependency), and the
obvious fix -- a `@<sha>` self-pin -- is impossible: a file cannot contain the hash of the
commit it lives in, so such a pin is always one commit stale and every release would need a
second commit just to move it.

The shape held here has no literal at all. Each workflow reads the commit and repository of
the workflow file that defines its job out of the job context (`job.workflow_sha`,
`job.workflow_repository`: the ref the caller pinned, resolved), checks exactly that out and
installs it through the composite action in that checkout, so the workflow and the toolchain
it runs are one commit and `verify-toolchain --expect-ref` compares the caller's pin against
that commit exactly. The fields are read through `toJSON(job)` because the pinned actionlint
(1.7.12) predates them; the step fails closed on anything but a 40-hex commit and an
owner/repository name. self-test.yml calls security-smoke.yml from this checkout on every
pull request, which is the in-repo proof that the mechanism works at the commit under test.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = ("security-full.yml", "security-smoke.yml")
TOOLCHAIN_CHECKOUT = ".thyn-sec-toolchain"
LOCAL_ACTION = f"./{TOOLCHAIN_CHECKOUT}"
PARKED = '"$RUNNER_TEMP/thyn-sec-source"'
CHECKOUT_ACTION = "actions/checkout@"
LOCATE = "Locate the toolchain commit this workflow runs from"
FETCH = "Fetch the toolchain at that commit"
PARK = "Park the toolchain source outside the scanned tree"
VERIFY = "Verify pins"
RETURN = "Return the toolchain source for the action's post steps"

# Any `uses:` of this repository by name -- the composite action or a workflow, at any ref -- is
# the literal self-reference this file exists to keep out.
_SELF_REF_RE = re.compile(r"^\s*-?\s*uses:\s*thyn-ai/security-toolchain(?:/\S*)?@", re.M)
_PINNED_USES_RE = re.compile(r"^\s*-?\s*uses:\s*\S+@[0-9a-f]{40}\s+#\s*v\d+\.\d+\.\d+\s*$")
# The words CodeQL's untrusted-checkout heuristics read as "this is a pull-request head":
# `.*(head|sha|commit).*` (SHA checkout) and `.*(head|branch|ref).*` (mutable-ref checkout).
_CODEQL_HEAD_NAME_RE = re.compile(r"head|sha|commit|branch|ref")
_USES_LINE_RE = re.compile(r"^\s*-?\s*uses:")


def _load(name: str) -> tuple[str, list[dict]]:
    text = (REPO / ".github" / "workflows" / name).read_text(encoding="utf-8")
    (job,) = yaml.safe_load(text)["jobs"].values()
    return text, job["steps"]


def _index(steps: list[dict], **key: str) -> int:
    ((field, value),) = key.items()
    found = [i for i, s in enumerate(steps) if s.get(field) == value]
    assert len(found) == 1, f"expected one step with {field}={value!r}, found {len(found)}"
    return found[0]


def _code_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_no_literal_self_reference_remains(workflow: str):
    text, _ = _load(workflow)
    assert not _SELF_REF_RE.search("\n".join(_code_lines(text))), (
        f"{workflow} references thyn-ai/security-toolchain by name: that literal can only ever "
        "name another commit than the one it lives in -- install through the self-located checkout"
    )


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_the_workflow_locates_its_own_commit_and_installs_exactly_that(workflow: str):
    _, steps = _load(workflow)

    locate = steps[_index(steps, id="self")]
    assert locate["name"] == LOCATE
    assert locate["env"] == {"JOB_CONTEXT": "${{ toJSON(job) }}"}
    run = locate["run"]
    assert "jq -r '.workflow_sha // empty'" in run
    assert "jq -r '.workflow_repository // empty'" in run
    assert "^[0-9a-f]{40}$" in run, "a value that is not a full commit sha must be refused"
    assert "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$" in run, "and so must one that is not owner/repo"
    assert "::error title=thyn-sec::" in run and "exit 1" in run
    assert 'echo "revision=$revision" >> "$GITHUB_OUTPUT"' in run
    assert 'echo "repository=$repository" >> "$GITHUB_OUTPUT"' in run

    fetch = steps[_index(steps, name=FETCH)]
    assert fetch["uses"].startswith(CHECKOUT_ACTION)
    assert fetch["with"] == {
        "repository": "${{ steps.self.outputs.repository }}",
        "ref": "${{ steps.self.outputs.revision }}",
        "path": TOOLCHAIN_CHECKOUT,
        "persist-credentials": False,
    }

    setup = steps[_index(steps, id="setup")]
    assert setup["uses"] == LOCAL_ACTION

    park = steps[_index(steps, name=PARK)]
    assert park["run"].strip() == f'mv "$GITHUB_WORKSPACE/{TOOLCHAIN_CHECKOUT}" {PARKED}'

    verify = steps[_index(steps, name=VERIFY)]
    assert verify["env"] == {"EXPECT_REF": "${{ steps.self.outputs.revision }}"}
    assert 'thyn-sec verify-toolchain --expect-ref "$EXPECT_REF"' in verify["run"]

    back = steps[-1]
    assert back["name"] == RETURN and back["if"] == "always()"
    assert f'mv {PARKED} "$GITHUB_WORKSPACE/{TOOLCHAIN_CHECKOUT}"' in back["run"]

    order = [
        _index(steps, id="self"),
        _index(steps, name=FETCH),
        _index(steps, id="setup"),
        _index(steps, name=PARK),
        _index(steps, name=VERIFY),
    ]
    assert order == sorted(order), "locate -> fetch -> install -> park -> verify, in that order"
    # the caller's own checkout comes before the toolchain's: actions/checkout cleans the
    # workspace it lands in, and would wipe a checkout made earlier
    callers = [
        i
        for i, s in enumerate(steps)
        if s.get("uses", "").startswith(CHECKOUT_ACTION) and "path" not in (s.get("with") or {})
    ]
    assert callers and callers[0] < order[0]
    # the caller's tree is scanned only once the toolchain source is out of it
    scans = [
        i
        for i, s in enumerate(steps)
        if "thyn-sec ci" in (s.get("run") or "") or "thyn-sec changed-files" in (s.get("run") or "")
    ]
    assert scans and min(scans) > _index(steps, name=PARK)


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_the_checkout_ref_stays_outside_codeqls_untrusted_head_heuristic(workflow: str):
    """A checkout `ref:` naming a step output whose name contains head/sha/commit (or
    head/branch/ref) is a pull-request head checkout to CodeQL's untrusted-checkout queries --
    by the name alone, with no dataflow from an event payload
    (`ActionsSHACheckout` / `ActionsMutableRefCheckout` in `UntrustedCheckoutQuery.qll`). Naming
    this output `sha` cost a high `actions/cache-poisoning` alert on the pull request that
    introduced it; `revision` says the same thing and is outside the guess.

    Checked on the YAML, which is where such an expression can appear at all: the same words in
    the locate step's shell script are the job-context field names being read, not a checkout
    argument, and are unaffected.
    """
    text, steps = _load(workflow)
    checkouts = [
        s
        for s in steps
        if s.get("uses", "").startswith(CHECKOUT_ACTION) and (s.get("with") or {}).get("ref")
    ]
    assert len(checkouts) == 1, "one checkout takes a ref: the toolchain at its own commit"
    for step in checkouts:
        ref = str(step["with"]["ref"])
        m = re.fullmatch(r"\$\{\{\s*steps\.(?P<id>[\w-]+)\.outputs\.(?P<field>[\w-]+)\s*\}\}", ref)
        assert m, f"checkout ref {ref!r} is not a plain step output of this job"
        for part, value in (("step id", m.group("id")), ("output name", m.group("field"))):
            assert not _CODEQL_HEAD_NAME_RE.search(value), (
                f"{workflow}: checkout ref {part} {value!r} contains a word CodeQL reads as a "
                "pull-request head (head/sha/commit/branch/ref); rename it"
            )
    assert "outputs.sha" not in text, "the sha -> revision rename must not regress anywhere"


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_every_remote_action_is_pinned_to_a_sha_with_a_version_comment(workflow: str):
    text, steps = _load(workflow)
    raw = [ln for ln in _code_lines(text) if _USES_LINE_RE.match(ln)]
    parsed = [s["uses"] for s in steps if "uses" in s]
    assert parsed and len(raw) == len(parsed), (raw, parsed)
    remote = [ln for ln in raw if not re.match(r"^\s*-?\s*uses:\s*\./", ln)]
    assert len(remote) == len(parsed) - 1, "exactly one local action: the self-located toolchain"
    for line in remote:
        assert _PINNED_USES_RE.match(line), f"not `@<40-hex sha> # vX.Y.Z`: {line.strip()}"


def test_both_workflows_share_one_installation_mechanism():
    """full and smoke must never drift apart on how they find and install the toolchain."""

    def mechanism(name: str) -> list[dict]:
        _, steps = _load(name)
        names = {"Checkout", LOCATE, FETCH, PARK, VERIFY, RETURN}
        kept = []
        for step in steps:
            if step.get("id") not in ("self", "setup") and step.get("name") not in names:
                continue
            step = dict(step)
            step["with"] = {
                k: v
                for k, v in (step.get("with") or {}).items()
                if k not in ("python-version", "prefetch")
            }
            kept.append(step)
        return kept

    assert mechanism("security-full.yml") == mechanism("security-smoke.yml")


def test_the_self_test_calls_a_reusable_workflow_from_this_checkout():
    """The in-repo proof: self-test.yml calls security-smoke.yml locally, so every pull request
    runs the self-location, the checkout at job.workflow_sha, the local install, the parked
    source tree and `verify-toolchain --expect-ref` against the exact commit under test."""
    doc = yaml.safe_load(
        (REPO / ".github" / "workflows" / "self-test.yml").read_text(encoding="utf-8")
    )
    calls = [
        j for j in doc["jobs"].values() if j.get("uses") == "./.github/workflows/security-smoke.yml"
    ]
    assert len(calls) == 1, "self-test.yml must call security-smoke.yml from this checkout once"
    assert calls[0]["permissions"] == {"contents": "read"}
    assert calls[0]["with"] == {"mode": "ratchet"}
