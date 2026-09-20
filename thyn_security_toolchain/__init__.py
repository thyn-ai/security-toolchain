"""thyn-ai security toolchain: pinned scanners as pre-commit hooks and a CI gate.

Everything here is standard-library only. The package is installed by pre-commit
into an isolated environment on developer machines and by ``pip install`` on CI
runners; scanner binaries are fetched on first use, verified against the sha256 in
``data/toolchain.lock.json``, and cached under ``~/.cache/thyn-sec``.
"""

__version__ = "0.1.14"
