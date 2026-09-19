"""Fuzz the changed-file derivation that scopes a pull-request scan (``changed.py``).

Properties, for arbitrary paths, list files, event payloads and environment values:

* ``MANIFEST_RE`` / ``IAC_RE`` classify any path without raising; ``ALL`` matches everything.
* ``write_list`` then ``read_list`` returns the list that was written (whitespace-trimmed,
  empty lines dropped) and ``ALL`` round-trips as ``ALL`` -- the file format the CI job hands
  from ``thyn-sec changed-files`` to ``thyn-sec ci`` loses nothing.
* ``from_github_event`` returns ``ALL`` or a sorted, duplicate-free list of strings for any
  JSON payload and any event name -- never an exception. The two things that would leave the
  process (the PR-files API and ``git diff``) are stubbed, so the harness exercises the
  decision logic only and never touches the network or a repository.
* ``_pushed_default_branch`` answers the default branch only when the pushed ref *is* that
  branch, and never raises on payload fields of the wrong type.
* ``opengrep_targets`` returns a subset of its input in input order, every entry an existing
  file with a scannable extension or a ``Dockerfile`` name.

Run: ``python fuzz/fuzz_changed.py fuzz/corpus/changed -max_total_time=60``
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _support import SeedProvider, Violation, check, json_value, run_main, text  # noqa: E402

from thyn_security_toolchain import changed  # noqa: E402

EVENT_KEYS = (
    "repository",
    "default_branch",
    "ref",
    "before",
    "after",
    "pull_request",
    "number",
    "base",
    "head",
    "sha",
)
EVENT_NAMES = ("push", "pull_request", "pull_request_target", "schedule", "workflow_dispatch", "")
REFS = ("refs/heads/main", "refs/heads/feature", "refs/tags/main", "main", "")
SHA_A = "a" * 40
SHA_B = "b" * 40
ENV_KEYS = (
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_REPOSITORY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "THYN_SEC_CHANGED_FILES",
)

WORK = Path(tempfile.mkdtemp(prefix="thyn-sec-fuzz-changed-"))
(WORK / "a.py").write_text("x = 1\n", encoding="utf-8")
(WORK / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
(WORK / "sub").mkdir()
(WORK / "sub" / "b.ts").write_text("export {};\n", encoding="utf-8")
(WORK / "img.png").write_bytes(b"\x89PNG")
EXISTING = ("a.py", "Dockerfile", "sub/b.ts", "img.png", "gone.py", "sub", "")
EVENT_FILE = WORK / "event.json"
LIST_FILE = WORK / "changed.txt"


def _stub_diff(state: dict[str, Any]):
    # Stands in for the whole of changed._git_diff, including its own refusal of revisions
    # that are not full SHAs (tests/test_malformed_inputs.py covers that guard directly).
    def diff(base: str, head: str, cwd: str | None = None):
        state["diff_calls"] += 1
        return state["diff_result"]

    return diff


def _stub_api(state: dict[str, Any]):
    def api(repo: str, number: int, token: str, server: str):
        state["api_calls"] += 1
        check(isinstance(number, int) and number > 0, f"PR files API asked for #{number!r}")
        return state["api_result"]

    return api


def _sha_or_junk(fdp: Any) -> Any:
    return fdp.PickValueInList([SHA_A, SHA_B, changed.ZERO_SHA, "-x", "", None, 7, "HEAD~1"])


def _event(fdp: Any) -> Any:
    if fdp.ConsumeIntInRange(0, 3) == 0:
        return json_value(fdp, EVENT_KEYS, depth=3)
    ev: dict[str, Any] = {}
    if fdp.ConsumeBool():
        ev["repository"] = (
            {"default_branch": fdp.PickValueInList(["main", "master", "", 5, None])}
            if fdp.ConsumeBool()
            else json_value(fdp, EVENT_KEYS, depth=1)
        )
    if fdp.ConsumeBool():
        ev["ref"] = fdp.PickValueInList(REFS) if fdp.ConsumeBool() else json_value(fdp, (), 0)
    if fdp.ConsumeBool():
        ev["before"], ev["after"] = _sha_or_junk(fdp), _sha_or_junk(fdp)
    if fdp.ConsumeBool():
        ev["pull_request"] = (
            {
                "number": fdp.PickValueInList([7, 0, -1, "7", None, True]),
                "base": {"sha": _sha_or_junk(fdp)},
                "head": {"sha": _sha_or_junk(fdp)},
            }
            if fdp.ConsumeBool()
            else json_value(fdp, EVENT_KEYS, depth=2)
        )
    if fdp.ConsumeBool():
        ev["number"] = fdp.PickValueInList([7, "7", None])
    return ev


def _files(fdp: Any) -> list[str]:
    return [
        fdp.PickValueInList(EXISTING) if fdp.ConsumeBool() else text(fdp, 30)
        for _ in range(fdp.ConsumeIntInRange(0, 6))
    ]


def _check_result(
    result: Any, label: str, none_ok: bool = False, sorted_unique: bool = True
) -> None:
    if changed.is_all(result) or (none_ok and result is None):
        return  # None: this source cannot answer and the next one is consulted
    check(isinstance(result, list), f"{label}: neither ALL nor a list")
    check(all(isinstance(p, str) for p in result), f"{label}: non-string path")
    if sorted_unique:  # derived lists are normalised; THYN_SEC_CHANGED_FILES is verbatim
        check(result == sorted(set(result)), f"{label}: not sorted and duplicate-free")


def exercise_event(fdp: Any, env: dict[str, str]) -> None:
    state = {
        "diff_calls": 0,
        "api_calls": 0,
        "diff_result": None if fdp.ConsumeBool() else _files(fdp),
        "api_result": None if fdp.ConsumeBool() else _files(fdp),
    }
    event = _event(fdp)
    payload = json.dumps(event) if fdp.ConsumeIntInRange(0, 9) else text(fdp, 20)
    EVENT_FILE.write_text(payload, encoding="utf-8")
    env["GITHUB_EVENT_NAME"] = fdp.PickValueInList(EVENT_NAMES)
    env["GITHUB_EVENT_PATH"] = str(EVENT_FILE) if fdp.ConsumeIntInRange(0, 9) else str(WORK)
    for key in ("GITHUB_REF", "GITHUB_REF_NAME"):
        if fdp.ConsumeBool():
            env[key] = fdp.PickValueInList(REFS)
    if fdp.ConsumeBool():
        env["GITHUB_REF_TYPE"] = fdp.PickValueInList(["branch", "tag", ""])
    if fdp.ConsumeBool():
        env["GITHUB_REPOSITORY"] = "thyn-ai/fixture"
    if fdp.ConsumeBool():
        # Any non-empty value selects the API path; the API itself is stubbed for the whole
        # iteration (see test_one_input), so no request ever leaves the process. An
        # environment value cannot hold NUL, so that byte is dropped.
        env["GITHUB_TOKEN"] = fdp.ConsumeUnicodeNoSurrogates(4).replace("\x00", "") or "t"
    changed._git_diff, changed._api_pr_files = _stub_diff(state), _stub_api(state)
    _check_result(changed.from_github_event(), "from_github_event", none_ok=True)
    if isinstance(event, dict):
        default = changed._pushed_default_branch(event)
        if default is not None:
            repo = event.get("repository")
            declared = repo.get("default_branch") if isinstance(repo, dict) else None
            check(
                isinstance(declared, str) and default == declared.strip(),
                "default branch answer is not the payload's default_branch",
            )
            # The same sources the code consults, read at this moment: the process
            # environment (env is applied to it later in the iteration) and the payload.
            ref = os.environ.get("GITHUB_REF") or (
                event.get("ref") if isinstance(event.get("ref"), str) else ""
            )
            if ref:
                check(ref == f"refs/heads/{default}", "default branch answered for other ref")
            else:
                check(
                    os.environ.get("GITHUB_REF_NAME") == default
                    and os.environ.get("GITHUB_REF_TYPE", "branch") != "tag",
                    "default branch answered without a matching ref name",
                )


def exercise_lists(fdp: Any) -> None:
    for path in [text(fdp, 60) for _ in range(fdp.ConsumeIntInRange(0, 4))]:
        changed.MANIFEST_RE.search(path)
        changed.IAC_RE.search(path)
    check(changed.any_match(changed.ALL, changed.IAC_RE), "ALL must match every pattern")

    # One path per line: a path may hold any character but the newline that ends its line and
    # the carriage return a Windows editor would add to it.
    lines = [text(fdp, 20).replace("\n", "").replace("\r", "") for _ in range(6)]
    lines = [ln for ln in lines if ln.strip()]
    if fdp.ConsumeBool():
        changed.write_list(changed.ALL, LIST_FILE)
        check(changed.read_list(LIST_FILE) == changed.ALL, "ALL did not round-trip")
    else:
        changed.write_list(lines, LIST_FILE)
        back = changed.read_list(LIST_FILE)
        expected = [ln.strip() for ln in lines]
        if expected == ["ALL"]:
            check(back == changed.ALL, "a single ALL line reads as ALL")
        else:
            check(back == expected, f"list round-trip changed the content: {back!r}")
    check(changed.describe(changed.ALL).startswith("ALL"), "describe(ALL)")

    files = _files(fdp)
    targets = changed.opengrep_targets(files, WORK)
    check(targets is not None, "a concrete list must give a concrete target list")
    check([p for p in files if p in targets] == targets, "targets are not an ordered subset")
    for p in targets:
        check((WORK / p).is_file(), f"target {p!r} is not an existing file")
        scannable = p.lower().endswith(changed.OPENGREP_EXT) or Path(p).name.startswith(
            "Dockerfile"
        )
        check(scannable, f"target {p!r} is not scannable by opengrep")
    check(changed.opengrep_targets(changed.ALL, WORK) is None, "ALL must mean a full scan")


def _never_leave_the_process(*args: Any, **kwargs: Any) -> None:
    raise Violation("the harness reached a network or git call that must stay stubbed")


def test_one_input(data: bytes, provider: type = SeedProvider) -> None:
    fdp = provider(data)
    saved = {k: os.environ.get(k) for k in ENV_KEYS}
    original_diff, original_api = changed._git_diff, changed._api_pr_files
    # Nothing in this harness may run git or call GitHub: both seams are replaced before any
    # code under test runs and restored afterwards, whatever the iteration did in between.
    changed._git_diff = changed._api_pr_files = _never_leave_the_process
    env: dict[str, str] = {}
    try:
        for key in ENV_KEYS:
            os.environ.pop(key, None)
        exercise_lists(fdp)
        exercise_event(fdp, env)
        os.environ.update(env)
        _check_result(changed.from_github_event(), "from_github_event(env)", none_ok=True)
        if fdp.ConsumeBool():
            os.environ["THYN_SEC_CHANGED_FILES"] = fdp.PickValueInList(
                [str(LIST_FILE), "ALL", "all", str(WORK / "missing"), ""]
            )
        _check_result(changed.changed_files(), "changed_files", sorted_unique=False)
    finally:
        changed._git_diff, changed._api_pr_files = original_diff, original_api
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def main(argv: list[str]) -> None:
    run_main(argv, test_one_input)


if __name__ == "__main__":
    main(sys.argv)
