# Fixtures

Each subdirectory holds exactly the input that should make **one** owner tool fail and
leave the other three silent. The self-test materializes them into a scratch git
repository before scanning: the `.fixture` suffix is dropped, `__JOIN__` markers are
joined, and `dockerfile` becomes `Dockerfile` (Trivy recognizes `Dockerfile.*` but not the
lowercase name, so the stored copy is invisible to it). Nothing in this repository is
therefore itself a secret, a vulnerable dependency or a misconfiguration -- the
toolchain's own gate stays clean without a single allowlist entry.

| directory   | owner tool   | what trips it                                                  |
|-------------|--------------|----------------------------------------------------------------|
| `gitleaks/` | gitleaks     | an AWS access key id (assembled at test time)                  |
| `opengrep/` | opengrep     | `subprocess.call(..., shell=True)` fed user input              |
| `osv/`      | osv-scanner  | `requests==2.19.0` in a requirements.txt; `lodash` 4.17.15 in an npm `package-lock.json` (no `package.json`, no integrity hashes: the lockfile alone is read, under any overlay) |
| `trivy/`    | trivy config | a root-user Dockerfile and a public-read S3 bucket in Terraform |
| `clean/`    | none         | ordinary code that must produce zero findings                  |
