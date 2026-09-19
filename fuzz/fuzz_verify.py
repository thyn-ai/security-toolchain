"""Fuzz the pin readers behind ``thyn-sec verify-toolchain`` (``verify.py``).

``precommit_rev`` and ``caller_pins`` are regex readers over a repository's
``.pre-commit-config.yaml`` and workflow files, and ``verify_repo`` combines them into the
list of pin problems a repository has. Properties, for any text and any small tree of files:

* Neither reader raises. ``precommit_rev`` returns ``None`` or a token without quotes,
  whitespace or ``#``; each pin from ``caller_pins`` is ``(workflow file, ref, comment)`` with
  a ``.yml``/``.yaml`` file name, a ref without whitespace or ``#`` and a comment that is
  ``None`` or a non-empty token.
* Commenting every line out (``# `` prefix) yields no pins: documentation never counts as a
  call. Indenting every line leaves the pins unchanged.
* ``verify_repo`` returns a list of strings for any generated tree, and an empty list for a
  tree whose pins all agree with the installed version.

Run: ``python fuzz/fuzz_verify.py fuzz/corpus/verify -max_total_time=60``
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _support import SeedProvider, check, run_main, text  # noqa: E402

from thyn_security_toolchain import verify  # noqa: E402

WORK = Path(tempfile.mkdtemp(prefix="thyn-sec-fuzz-verify-"))
TAG = verify.installed_tag()
SHA = "c" * 40
FRAGMENTS = (
    f"repo: {verify.REPO_URL}\n",
    f"    rev: {TAG}\n",
    "    rev: 'v0.0.1'\n",
    '    rev: "v9.9.9"  # comment\n',
    "default_install_hook_types: [pre-commit, pre-push]\n",
    "default_install_hook_types: [pre-commit]\n",
    f"    uses: thyn-ai/security-toolchain/.github/workflows/security-full.yml@{SHA} # {TAG}\n",
    f"    uses: thyn-ai/security-toolchain/.github/workflows/security-smoke.yml@{SHA} # {TAG}\n",
    "    uses: thyn-ai/security-toolchain/.github/workflows/security-full.yml@main\n",
    f"    uses: thyn-ai/security-toolchain/.github/workflows/security-full.yml@{SHA}\n",
    "# uses: thyn-ai/security-toolchain/.github/workflows/security-full.yml@<sha> # vX.Y.Z\n",
    "uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7.0.0\n",
    "repos:\n",
    "  - repo: local\n",
    "\n",
    "\t\n",
    "\x00\n",
)


def _text(fdp: Any) -> str:
    parts = []
    for _ in range(fdp.ConsumeIntInRange(0, 8)):
        parts.append(fdp.PickValueInList(FRAGMENTS) if fdp.ConsumeBool() else text(fdp, 40))
    return "".join(parts)


def exercise_readers(sample: str) -> None:
    rev = verify.precommit_rev(sample)
    if rev is not None:
        check(isinstance(rev, str) and rev != "", "precommit_rev returned an empty token")
        check(not any(c in rev for c in " \t\n'\"#"), f"precommit_rev token {rev!r} is not clean")
    pins = verify.caller_pins(sample)
    for name, ref, comment in pins:
        check(name.endswith((".yml", ".yaml")), f"pin names a non-workflow file {name!r}")
        check(ref != "" and not any(c in ref for c in " \t\n#"), f"pin ref {ref!r} is not clean")
        check(
            comment is None or (comment != "" and not any(c in comment for c in " \t\n")),
            f"pin comment {comment!r} is not a token",
        )
    commented = "".join(f"# {ln}\n" for ln in sample.splitlines())
    check(verify.caller_pins(commented) == [], "a commented-out call counted as a pin")
    indented = "".join(f"    {ln}\n" for ln in sample.splitlines())
    check(verify.caller_pins(indented) == pins, "indentation changed the pins")


def exercise_repo(fdp: Any) -> None:
    root = WORK / "repo"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir()
    if fdp.ConsumeBool():
        (root / ".pre-commit-config.yaml").write_text(_text(fdp), encoding="utf-8")
    if fdp.ConsumeBool():
        wf = root / ".github" / "workflows"
        wf.mkdir(parents=True)
        for i in range(fdp.ConsumeIntInRange(0, 3)):
            suffix = ".yml" if fdp.ConsumeBool() else ".yaml"
            (wf / f"w{i}{suffix}").write_text(_text(fdp), encoding="utf-8")
    expect = fdp.PickValueInList([None, TAG, SHA, "v0.0.1", "d" * 40])
    problems = verify.verify_repo(root, expect)
    check(isinstance(problems, list), "verify_repo must return a list")
    check(all(isinstance(p, str) and p for p in problems), "verify_repo: empty problem text")


def test_one_input(data: bytes, provider: type = SeedProvider) -> None:
    exercise_readers(data.decode("utf-8", errors="replace"))
    fdp = provider(data)
    exercise_readers(_text(fdp))
    exercise_repo(fdp)


def main(argv: list[str]) -> None:
    run_main(argv, test_one_input)


if __name__ == "__main__":
    main(sys.argv)
