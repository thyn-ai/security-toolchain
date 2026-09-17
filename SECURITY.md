# Security policy

This repository distributes configuration and a small Python launcher; it contains no
secrets and runs no service. What matters here is the integrity of the pins.

* Every scanner binary is downloaded from its upstream GitHub release and verified against
  the sha256 recorded in `security/toolchain.lock` before it is executed. A digest mismatch
  is a hard failure, never a warning.
* Pins are bumped only through pull requests to this repository; consuming repositories
  reference a commit SHA (CI) and a tag (pre-commit) that `verify-toolchain` cross-checks.

If you believe a pinned version is compromised or a digest is wrong, open a security
advisory on this repository or email security@thyn.ai. Please do not open a public issue
for anything that could be exploited before a fix lands.
