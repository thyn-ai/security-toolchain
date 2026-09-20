# Fuzz harnesses

Coverage-guided fuzzing of every parser in the toolchain, with
[atheris](https://github.com/google/atheris) (libFuzzer for Python). The toolchain executes
pinned binaries on the strength of what these parsers read -- the lock file is the trust root,
the overlay file chooses the rules, the report parsers decide what fails a gate -- so each of
them must fail only in its documented way, whatever it is fed.

| harness              | code under test                                   | property                                                                                                     |
|----------------------|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| `fuzz_lock.py`       | `lock.validate_lock`                              | returns or raises `LockError`; an accepted lock has a version, a GitHub https URL and a 64-hex sha256 per asset |
| `fuzz_overlays.py`   | `hooks.resolve_overlay`                           | returns lists of strings or raises `ScanError`; parents first, no duplicates, cycles terminate, repeatable    |
| `fuzz_changed.py`    | `changed.py` regexes, list format, event reader   | any path classifies; `write_list`/`read_list` round-trip; any payload gives `ALL` or a sorted list           |
| `fuzz_reports.py`    | `gate.PARSERS`, the two SARIF rewriters           | findings or `ValueError`; keys line-independent and repeatable; rewriters idempotent; normalisers idempotent |
| `fuzz_verify.py`     | `verify.precommit_rev`, `caller_pins`, `verify_repo` | clean tokens, comments never count, indentation is irrelevant, `verify_repo` always answers a list        |

Each harness feeds every input twice: once as raw bytes on disk (the file a scanner or a
developer might hand the toolchain) and once through `FuzzedDataProvider` to build a
structure-aware document -- a mutation of the shipped lock, a SARIF with the keys the parser
looks up and deliberate type confusion in some of them. Properties are checked with
`_support.check`, never `assert`, so they hold under `python -O` and a failure names the
property rather than a line inside the code under test.

## Running

atheris ships Linux wheels; on macOS it needs a clang with libFuzzer. The CI job runs on
`ubuntu-latest`:

```bash
python -m pip install --require-hashes -r requirements-fuzz.txt
python -m pip install --no-deps -e .
mkdir -p /tmp/fuzz-work/lock
python fuzz/fuzz_lock.py /tmp/fuzz-work/lock fuzz/corpus/lock -max_total_time=60 -timeout=25
```

Every `fuzz_*.py` takes libFuzzer's arguments: corpus directories first, flags after. libFuzzer
writes the inputs it discovers into the *first* directory, so give it a scratch directory and
the committed seeds second (the CI job does the same); passing `fuzz/corpus/<name>` alone
works but grows the checkout. `-max_total_time` bounds a run in seconds; `-runs=N` bounds it
in iterations; `-timeout` turns a slow input (a regex that backtracks, a pathological path)
into a failure. A crash or a property violation writes `crash-<sha1>` next to the harness (or
under `-artifact_prefix=<dir>/`); reproduce it with `python fuzz/fuzz_<name>.py crash-<sha1>`.

Without atheris the properties still run: `tests/test_fuzz_harnesses.py` replays every
committed corpus file and a fixed set of byte patterns through each harness's
`test_one_input(data, SeedProvider)` on every Python in the matrix, so a regression in a
property is caught by `pytest -m "not integration"` before the fuzz job starts.

## Corpus

`corpus/<harness>/` holds a few real documents per harness (the shipped lock and overlay files,
one report per scanner, a changed-files list, a pre-commit block and a caller workflow). They
give the fuzzer a starting point close to the accepted shapes; it discovers the rest. Add a
file when a new shape becomes valid; keep the directories small and readable.

## Findings so far

The harnesses were written against the code as it stood, and the first minutes found the same
class of defect in four places: a field of the wrong JSON type reached an attribute access
and surfaced as `AttributeError`/`TypeError` instead of the documented error. All four are
fixed in the same change that added the harnesses (`lock.validate_lock` -> `LockError`,
`hooks.resolve_overlay` -> `ScanError` for an unknown parent or a bare-string field,
`gate` parsers and rewriters -> `ReportError`, `changed.from_github_event` -> `ALL`), and
`changed._git_diff` now refuses revisions that are not full commit SHAs before they become a
`git` argument.
