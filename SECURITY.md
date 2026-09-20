# Security policy

This repository distributes scanner configuration and a small Python launcher; it contains no
secrets and runs no service. What matters here is the integrity of the pins, and that is what
this policy covers.

## What the toolchain guarantees

* Every scanner binary is downloaded from its upstream GitHub release and verified against
  the sha256 recorded in `security/toolchain.lock` before it is executed. A digest mismatch
  is a hard failure, never a warning.
* Pins are bumped only through pull requests to this repository; consuming repositories
  reference a commit SHA (CI) and a tag (pre-commit) that `verify-toolchain` cross-checks.
* The parsers that read the lock, the overlay file and every scanner report are fuzzed on
  each push (`fuzz/README.md`) so a malformed input fails in its documented way rather than
  being misread.

## Supported versions

Fixes land on `main` and in the latest tagged release, which `scripts/propagate.py` fans out
to every repository in `fleet.json`. Older tags stay available for reproducibility but are
not patched; a repository pinned to one should move to the latest release.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for security problems.**
Public disclosure before a fix is available puts every repository that runs this toolchain
at risk.

Report privately through either channel:

1. **GitHub Security Advisories** (preferred) -- open a private report from this
   repository's **Security -> Report a vulnerability** tab.
2. **Email** -- `security@thyn.ai`.

Please include, where possible: the pinned version or digest you believe is wrong or
compromised, the tool and platform it affects, how you established it (a checksum file, an
upstream advisory, a reproduction), and the toolchain release you tested.

## What to expect

* Acknowledgement within 3 business days.
* An initial assessment and severity triage within 7 business days.
* A compromised or wrong pin is treated as critical: the lock is corrected in a reviewed pull
  request, a new release is tagged and propagated to the fleet, and the advisory names the
  affected releases.
* Coordinated disclosure: we agree on a timeline with you and publish a GitHub Security
  Advisory once the fix is released, with credit unless you prefer to remain anonymous.

## Scope

**In scope:** the contents of `security/toolchain.lock` (versions, URLs, digests), the
launcher and hooks in `thyn_security_toolchain/`, the reusable workflows and the composite
action in this repository, and `scripts/propagate.py`.

**Out of scope for this repository:** vulnerabilities in the scanners themselves (Gitleaks,
Opengrep, OSV-Scanner, Trivy, actionlint) or in the opengrep-rules bundle -- report those
upstream; we still want to hear how they affect a pinned release so the pin can move. The
Algenta engine and the other thyn-ai repositories have their own security policies.
