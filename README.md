# thyn-ai security toolchain

One pinned, checksum-verified set of open-source scanners, run the same way on a
developer's machine and on a clean CI checkout:

| category                      | owner tool                                      | where it runs                                    |
|-------------------------------|-------------------------------------------------|--------------------------------------------------|
| secrets                       | [Gitleaks](https://github.com/gitleaks/gitleaks) | every commit (staged), every push (range), CI    |
| static analysis (SAST)        | [Opengrep](https://github.com/opengrep/opengrep) | changed files at commit, full repo at push, CI   |
| dependency vulnerabilities    | [OSV-Scanner](https://github.com/google/osv-scanner) | push, CI (when a manifest or lockfile changed) |
| infrastructure misconfig      | [Trivy](https://github.com/aquasecurity/trivy) `config` | push, CI (when an IaC file changed)     |
| workflow syntax               | [actionlint](https://github.com/rhysd/actionlint) | commit                                         |

One owner per category, on purpose: a secret is reported by Gitleaks and nobody else; a
Dockerfile misconfiguration by Trivy and nobody else. Container image CVEs and SBOMs stay
with the syft/grype pipeline that already publishes them.

## Use it in a repository

Three files, no copied scanner configuration:

```yaml
# .pre-commit-config.yaml
default_install_hook_types: [pre-commit, pre-push]
repos:
  # thyn-security-toolchain:begin
  - repo: https://github.com/thyn-ai/security-toolchain
    rev: v0.1.12
    hooks:
      - id: gitleaks-staged
      - id: opengrep-changed
        args: ["--overlay=python-uv"]
      - id: actionlint
      - id: verify-toolchain
      - id: gitleaks-push
      - id: opengrep-full
        args: ["--overlay=python-uv"]
      - id: osv-scan
      - id: trivy-config
      - id: security-fix-deps
  # thyn-security-toolchain:end
```

```yaml
# .github/workflows/security.yml
jobs:
  full:
    uses: thyn-ai/security-toolchain/.github/workflows/security-full.yml@<sha> # v0.1.12
    permissions: { contents: read, security-events: write, pull-requests: read, actions: read }
    with: { overlay: python-uv, mode: advisory }
```

```text
security/baseline/<tool>.txt      # measured on CI, may only shrink (see below)
```

If the repository runs Dependabot on `github-actions`, exclude this toolchain so the CI
pin and the pre-commit `rev` are only ever bumped together by `propagate.py`. Dependabot
names a reusable-workflow dependency by its full path, so the pattern needs a wildcard:

```yaml
    ignore:
      - dependency-name: "thyn-ai/security-toolchain*"
```

`pre-commit install` installs both stages. The first run fetches the pinned binaries into
`~/.cache/thyn-sec` (about 250 MB, verified against `security/toolchain.lock`); after that
the commit-time hooks take a few seconds and the push-time hooks under two minutes on a
typical repository.

Full templates live in [`templates/`](templates/); `scripts/propagate.py` applies them to
every repository in [`fleet.json`](fleet.json) and bumps pins on each release.

## How findings are judged

The same gate runs everywhere: `thyn-sec ci` on CI, one tool at a time in the hooks.

* **advisory** mode (the default for a newly onboarded repository) surfaces every finding
  as a warning and never fails.
* **ratchet** mode fails only on a *new* HIGH/CRITICAL finding -- one whose key is not in
  the committed `security/baseline/<tool>.txt`. Keys are line-number independent, so
  editing above a known finding does not churn the file.
* Baselines are **measured on CI** (`workflow_dispatch` → `measure_baseline: true`,
  download the artifact, commit it as-is) and **may only shrink**: the gate tells you which
  entries are no longer observed so you can delete them.
* Secrets are never baselined. Allowlist a reviewed false positive through
  `.gitleaksignore` (fingerprints) or `.gitleaks.toml` (paths); rotate anything real.
* Suppressions live in those files, never in inline `nosemgrep` / `# nosec` comments.
* Opengrep **audit rules** -- registry rules tagged `LOW CONFIDENCE` or with `.audit.` /
  `-audit` in their id (`dangerous-subprocess-use-audit`, `non-literal-import`,
  `dynamic-urllib-use-detected`, ...) -- flag intended subprocess, import and URL use. They
  score MEDIUM so they never block, they are counted in the console summary and kept in the
  `thyn-sec-reports` artifact, but they are **left out of the SARIF uploaded to code
  scanning** so the alert list stays actionable. A repository that wants them as
  code-scanning warnings sets `opengrep_upload_audit: true` on `security-full.yml`.
* **Test code is out of Opengrep's scope**: `**/tests/**`, `**/test/**`, `**/__tests__/**`,
  `test_*.py`, `*_test.py`, `conftest.py`, `*.test.ts|tsx|js`, `*.spec.ts|tsx|js`,
  `**/testdata/**`, `**/fixtures/**`. What SAST finds there is the fixture, not a defect: a
  hard-coded JWT secret that mints test tokens, `jwt.decode` without verification on a token
  the test itself just signed, XML parsing of a checked-in sample, `subprocess` in a test
  harness. The scanner applies the exclusion itself (`--exclude` + `--force-exclude`), so it
  holds for the pre-commit hooks, the PR-scoped CI scan and the full scan alike, and the
  results never exist -- not in the gate, not in the code-scanning upload. Opengrep's default
  `.semgrepignore` already skips `tests/` and `test/`, but a repository's own `.semgrepignore`
  replaces that default and files named on the command line bypass it without
  `--force-exclude`; this policy holds either way. `benchmarks/`, `scripts/` and every other
  non-test path stay in scope. A repository that wants its tests scanned sets
  `opengrep_scan_tests: true` on `security-full.yml` (`thyn-sec ci --opengrep-scan-tests`;
  `--scan-tests` on the `opengrep-changed` / `opengrep-full` hooks). That lifts this
  toolchain's exclusion only: Opengrep's built-in `.semgrepignore` still skips `tests/` and
  `test/` -- on a full scan and, because `--force-exclude` applies it to files named on the
  command line too, on the PR-scoped CI scan and the `opengrep-changed` hook alike -- until
  the repository commits a `.semgrepignore` of its own (an empty one is enough); the gate
  summary says so when it applies.

On pull requests the CI job scopes Opengrep to the changed files and skips OSV-Scanner
or Trivy when no manifest or infrastructure file changed; the list is derived fail-closed
(anything uncertain widens to a full scan). Pushes to `main` and the weekly schedule scan
everything.

## Overlays

An overlay is the set of Opengrep rule packs for a repository class, and nothing more:
`python-uv` (Python), `site` (Next.js/TypeScript), `python-javascript` (Python +
JavaScript/TypeScript), `engine`, `codna`, `smoke`. Packs come from a pinned commit of
[opengrep-rules](https://github.com/opengrep/opengrep-rules), fetched into the cache at
scan time; a repository can add its own rules under `security/opengrep/*.yml`.
`thyn-sec overlays -v` lists what each one loads.

The overlay name never reaches the other scanners. OSV-Scanner walks the whole tree
(`osv-scanner scan source --recursive`) and reads every lockfile it supports --
`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`, `poetry.lock`,
`requirements.txt`, `pixi.lock`, `go.sum`, `Cargo.lock`, ... -- so an npm workspace, a pnpm
workspace and a uv project are scanned identically under any overlay, and on a pull request
a change to any of those files puts the scan in scope. Trivy `config` and Gitleaks take the
whole tree as well. `pnpm-monorepo` is the pre-0.1.12 name of `python-javascript`, kept as
an alias so repositories onboarded with it keep working; it never selected lockfiles.

## Pinning and verification

`security/toolchain.lock` is the single source of truth for every tool version and the
sha256 of each release asset per platform. Nothing is executed before its digest matches.
`verify-toolchain` (a hook and a CI step) checks that the `rev:` in pre-commit, the
`@<sha> # vX.Y.Z` pin of the caller workflow and the installed toolchain agree, and that
CI pins by commit SHA.

The CI job runs on standard GitHub-hosted runners only and refuses billed runner labels.

## Commands

```text
thyn-sec ci --overlay <name> --mode advisory|ratchet [--changed FILE|ALL] [--measure-baseline] [--opengrep-upload-audit] [--opengrep-scan-tests]
thyn-sec changed-files [--output FILE]
thyn-sec install all --rules          # prefetch everything (CI, air-gapped prep)
thyn-sec run trivy -- image ...       # any pinned tool, verbatim
thyn-sec lock | overlays -v | verify-toolchain
```

Environment: `THYN_SEC_CACHE_DIR`, `THYN_SEC_OFFLINE=1` (cache misses become errors),
`THYN_SEC_OSV_OFFLINE=1` (query a locally cached OSV database), `THYN_SEC_VERBOSE=1`.

## Governance

Toolchain code: Apache-2.0. Scanners are used as unmodified upstream binaries: Gitleaks
(MIT), Opengrep (LGPL-2.1), OSV-Scanner (Apache-2.0), Trivy (Apache-2.0), actionlint
(MIT). The opengrep-rules bundle (LGPL-2.1 with the Commons Clause) is fetched at scan
time and not redistributed here. No scanner in this toolchain sends code or credentials
to a third party; OSV-Scanner queries the public OSV API with package coordinates unless
`THYN_SEC_OSV_OFFLINE=1` is set.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]" ruff
pytest -m "not integration"     # fast
pytest -m integration           # downloads the pinned scanners, proves one-owner-per-fixture
```

Releasing: bump `version` in `pyproject.toml` and `__init__.py`, bump the
`thyn-ai/security-toolchain@vX.Y.Z` reference in both reusable workflows, tag `vX.Y.Z`,
publish the release. `propagate.yml` (or `scripts/propagate.py`) opens the pin-bump pull
requests across the fleet -- see the next section for what the workflow needs.

## Running propagate from GitHub Actions

`propagate.yml` runs on every published release, and on `workflow_dispatch` with `tag`,
`repos` and `dry_run`. It needs a token that can push a branch and open a pull request in
every fleet repository, including a change to `.github/workflows/security.yml`. The default
`GITHUB_TOKEN` cannot (enterprise policy forbids it from creating pull requests, and it has
no `workflows` permission), so the job reads one of two credentials. With neither present it
posts a `::notice` and exits 0 -- which is what every run through v0.1.10 did, because the
secret never existed; each of those releases was fanned out from a laptop instead.

The secrets are read in exactly two places: the `creds` step tests their presence in the
expression layer (`${{ secrets.NAME != '' }}`, so booleans reach its shell and no secret value
does), then the App id and key go only to the token-mint action and `TOOLCHAIN_PROPAGATE_TOKEN`
enters the Propagate step's environment only when it is the credential in use. On the `release`
trigger the job also refuses to fan out unless the tagged commit is reachable from `main` (the
compare API reports `identical` or `behind`) and its `__version__` equals the tag, because
`release: published` fires for a tag on any commit and an unreviewed one would otherwise reach
every fleet repository with the org token.

**GitHub App (preferred).** Two repository secrets, named exactly as in
`algenta-integrations` so the owner sets them the same way:

| secret                            | value                                    |
|-----------------------------------|------------------------------------------|
| `ALGENTA_SDK_SYNC_APP_ID`         | the App's numeric id (public)            |
| `ALGENTA_SDK_SYNC_APP_PRIVATE_KEY` | the App's private key, the PEM as downloaded |

```bash
gh secret set ALGENTA_SDK_SYNC_APP_ID -R thyn-ai/security-toolchain --body <app-id>
gh secret set ALGENTA_SDK_SYNC_APP_PRIVATE_KEY -R thyn-ai/security-toolchain < <path-to-pem>
```

The App must be installed on every repository in `fleet.json` with the repository permissions
**Contents: read and write**, **Pull requests: read and write** and **Workflows: read and
write** (the bump rewrites `.github/workflows/security.yml`; GitHub refuses the push without
it). Each run mints a short-lived installation token narrowed to exactly those plus
`metadata: read`, and the pull requests are authored by the App's bot user, with no personal
or assistant attribution. A repository the App is not installed on shows up as one `FAILED`
line for that repository while the rest fan out. If the token cannot be minted at all (a
permission missing from the App, the App not installed on the organization, a rotated key),
the job fails with an `::error` that says so rather than silently doing nothing.

**Fine-grained PAT (alternative).** `TOOLCHAIN_PROPAGATE_TOKEN`: a fine-grained personal
access token limited to the fleet repositories with the same three permissions (Contents,
Pull requests, Workflows: read and write). Commits then carry `propagate.py`'s default
author. The App secrets take precedence when both are present.

```bash
gh secret set TOOLCHAIN_PROPAGATE_TOKEN -R thyn-ai/security-toolchain
```

Every run writes a step summary naming the credential mode and, per repository, whether a
pull request was opened, the repository was already at the tag, or the fan-out failed.

## Related repositories

Open-source repositories from the Algenta team. The Algenta engine itself is proprietary; everything listed here is Apache-2.0. Issues and discussions are welcome in whichever repository owns the code.

- [thyn-ai/algenta-sdk](https://github.com/thyn-ai/algenta-sdk) — Python & TypeScript SDKs for the Algenta decision engine: governed tool profiles, execution receipts, approvals.
- [thyn-ai/algenta-integrations](https://github.com/thyn-ai/algenta-integrations) — Framework integrations for Algenta: LangChain, LlamaIndex, pydantic-ai, MAF, Haystack, LiteLLM, Ray Serve, vLLM, Vercel AI SDK and n8n.
- [thyn-ai/mojo-kernels](https://github.com/thyn-ai/mojo-kernels) — Clean-room Mojo kernels as drop-in accelerators for popular Python/TypeScript libraries, with bit-exact parity and pure-language fallbacks.
- [thyn-ai/security-toolchain](https://github.com/thyn-ai/security-toolchain) (this repository) — The pinned, checksum-verified security toolchain (Gitleaks, Opengrep, OSV-Scanner, Trivy config, actionlint) that every thyn-ai repository runs locally and in CI.
- [thyn-ai/feedback](https://github.com/thyn-ai/feedback) — Public issue intake for the Algenta family of open-source projects and the Codna GitHub App.
- [thyn-ai/codna-action](https://github.com/thyn-ai/codna-action) — Public GitHub Action wrapper for Codna.
