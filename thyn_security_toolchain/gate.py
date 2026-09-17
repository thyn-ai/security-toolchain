"""Baseline ratchet shared by every scanner.

Modeled on the engine's ``scripts/ci_blast_radius_gate.py`` and
``tests/blast_radius_known_red.txt``: a committed, human-readable list of *known*
finding keys that was **measured on CI** and may only shrink. A finding whose key is
in the baseline is reported as known debt; a finding whose key is not is *new* and
fails the gate in ``ratchet`` mode. With no baseline file present the gate is
advisory: every finding is surfaced as a warning and the exit code is 0.

Keys are deliberately line-number independent so that unrelated edits above a
finding do not churn the baseline:

* opengrep  ``<rule_id> :: <path> :: <normalized snippet>``
* trivy     ``<check id> :: <path>``
* osv       ``<ecosystem>/<package>@<version> :: <advisory id>``
* gitleaks  gitleaks' own fingerprint ``<path>:<rule>:<line>`` (allowlisted via .gitleaksignore,
            never via a baseline — secrets are zero-tolerance)
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
BLOCKING_MIN = "HIGH"

HEADER_MARKER = "MEASURED ON CI"


@dataclass
class Finding:
    tool: str
    key: str
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    path: str
    line: int | None
    message: str
    rule: str
    extra: dict[str, str] = field(default_factory=dict)

    @property
    def blocking(self) -> bool:
        return SEVERITY_ORDER.get(self.severity, 0) >= SEVERITY_ORDER[BLOCKING_MIN]


@dataclass
class GateResult:
    tool: str
    mode: str
    baseline_present: bool
    new: list[Finding]
    known: list[Finding]
    fixed: list[str]  # baseline keys no longer observed (the file may shrink)
    ignored_low: int  # findings below the blocking threshold that are not baselined

    @property
    def exit_code(self) -> int:
        if self.mode != "ratchet" or not self.baseline_present:
            return 0
        return 1 if any(f.blocking for f in self.new) else 0

    @property
    def summary(self) -> str:
        blocking_new = sum(1 for f in self.new if f.blocking)
        state = "advisory" if (self.mode != "ratchet" or not self.baseline_present) else "ratchet"
        base = "no baseline" if not self.baseline_present else f"{len(self.known)} known"
        return (
            f"{self.tool}: {len(self.new)} new ({blocking_new} blocking), {base}, "
            f"{len(self.fixed)} fixed, {self.ignored_low} below threshold [{state}]"
        )


# --------------------------------------------------------------------------- helpers


def _norm_ws(text: str, limit: int = 100) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:limit]


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return (
            "MEDIUM"  # unknown severity never blocks on its own; the baseline can still absorb it
        )
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _rel(uri: str, root: Path | None) -> str:
    """Normalize a tool-reported location to a path relative to the repo root.

    Tools disagree: SARIF gives ``file:///abs/path`` or ``%SRCROOT%``-relative, osv-scanner
    prints an absolute path with its leading slash stripped. Try each reading and keep the
    first one that lands inside *root*; otherwise return the cleaned input unchanged.
    """
    uri = uri or ""
    if uri.startswith("file://"):
        uri = uri[len("file://") :]
    if root is not None:
        root_resolved = root.resolve()
        for candidate in (uri, "/" + uri.lstrip("/")):
            try:
                return str(Path(candidate).resolve().relative_to(root_resolved))
            except (ValueError, OSError):
                continue
    return uri.lstrip("./")


# --------------------------------------------------------------------------- parsers

_OPENGREP_PREFIX = re.compile(r"^.*?opengrep-rules-[0-9a-f]{12}\.")


def normalize_opengrep_rule_id(rule_id: str) -> str:
    """Strip the cache-path prefix opengrep prepends when rules are loaded from a directory.

    ``--no-rewrite-rule-ids`` avoids this at scan time; this is the belt to that suspender
    so baselines stay stable even if a caller forgets the flag.
    """
    return _OPENGREP_PREFIX.sub("", rule_id)


_AUDIT_RULE_ID = re.compile(r"(^|\.)audit\.|-audit$")


def _is_low_confidence_rule(rule_id: str, meta: dict) -> bool:
    tags = (meta.get("properties") or {}).get("tags") or []
    if any(str(t).upper() == "LOW CONFIDENCE" for t in tags):
        return True
    return bool(_AUDIT_RULE_ID.search(normalize_opengrep_rule_id(rule_id)))


def demote_low_confidence_levels(path: Path) -> int:
    """Rewrite an Opengrep SARIF in place so low-confidence / audit rules carry level ``warning``.

    The gate below already scores them MEDIUM, but GitHub reads the SARIF itself: an ``error``
    result turns the code-scanning check red and trips a ``code_quality`` ruleset on the caller,
    so an audit hint on intended subprocess use blocked thyn-ai/codna#508 even in advisory mode.
    Real (non-audit) rules keep their level. Returns how many results changed effective level.
    Idempotent; a file with nothing to demote is not rewritten.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    demoted = 0
    for run in data.get("runs", []):
        rules = (run.get("tool", {}).get("driver", {}) or {}).get("rules", []) or []
        low_rules: set[str] = set()
        default_demoted: set[str] = set()
        for rule in rules:
            rid = rule.get("id", "")
            if not _is_low_confidence_rule(rid, rule):
                continue
            low_rules.add(rid)
            cfg = rule.setdefault("defaultConfiguration", {})
            if cfg.get("level") == "error":
                cfg["level"] = "warning"
                default_demoted.add(rid)
        for res in run.get("results", []) or []:
            rid = res.get("ruleId")
            if rid not in low_rules:
                continue
            if res.get("level") == "error":
                res["level"] = "warning"
                demoted += 1
            elif "level" not in res and rid in default_demoted:
                demoted += 1
    if demoted:
        path.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    return demoted


def parse_opengrep_sarif(path: Path, root: Path | None = None) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[Finding] = []
    for run in data.get("runs", []):
        rules = {
            r.get("id"): r for r in (run.get("tool", {}).get("driver", {}) or {}).get("rules", [])
        }
        for res in run.get("results", []):
            raw_id = res.get("ruleId", "")
            rule = normalize_opengrep_rule_id(raw_id)
            meta = rules.get(raw_id, {})
            level = res.get("level") or (meta.get("defaultConfiguration") or {}).get(
                "level", "warning"
            )
            severity = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "MEDIUM")
            tags = (meta.get("properties") or {}).get("tags") or []
            if severity == "HIGH" and any(str(t).upper() == "LOW CONFIDENCE" for t in tags):
                # Semgrep-convention `confidence: LOW` marks audit rules: worth a look, never a
                # merge blocker. They stay visible as warnings and can still be baselined.
                severity = "MEDIUM"
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = _rel(loc.get("artifactLocation", {}).get("uri", ""), root)
            region = loc.get("region", {}) or {}
            snippet = _norm_ws((region.get("snippet") or {}).get("text", ""))
            out.append(
                Finding(
                    tool="opengrep",
                    key=f"{rule} :: {uri} :: {snippet}",
                    severity=severity,
                    path=uri,
                    line=region.get("startLine"),
                    message=_norm_ws(res.get("message", {}).get("text", ""), 300),
                    rule=rule,
                )
            )
    return out


def parse_trivy_sarif(path: Path, root: Path | None = None) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[Finding] = []
    for run in data.get("runs", []):
        rules = {
            r.get("id"): r for r in (run.get("tool", {}).get("driver", {}) or {}).get("rules", [])
        }
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id, {})
            score_text = (rule.get("properties") or {}).get("security-severity")
            try:
                score = float(score_text) if score_text is not None else None
            except ValueError:
                score = None
            severity = _severity_from_score(score)
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = _rel(loc.get("artifactLocation", {}).get("uri", ""), root)
            region = loc.get("region", {}) or {}
            title = (rule.get("shortDescription") or {}).get("text", "")
            out.append(
                Finding(
                    tool="trivy",
                    key=f"{rule_id} :: {uri}",
                    severity=severity,
                    path=uri,
                    line=region.get("startLine"),
                    message=_norm_ws(title or res.get("message", {}).get("text", ""), 300),
                    rule=rule_id,
                )
            )
    # trivy reports one result per occurrence; the key collapses to (check, file)
    seen: set[str] = set()
    deduped: list[Finding] = []
    for f in out:
        if f.key in seen:
            continue
        seen.add(f.key)
        deduped.append(f)
    return deduped


def _pick_advisory_id(ids: Sequence[str]) -> str:
    ghsa = sorted(i for i in ids if i.startswith("GHSA-"))
    if ghsa:
        return ghsa[0]
    cve = sorted(i for i in ids if i.startswith("CVE-"))
    if cve:
        return cve[0]
    return sorted(ids)[0] if ids else "UNKNOWN"


def parse_osv_json(path: Path, root: Path | None = None) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    out: list[Finding] = []
    for result in data.get("results", []) or []:
        source = _rel((result.get("source") or {}).get("path", ""), root)
        for pkg in result.get("packages", []) or []:
            info = pkg.get("package") or {}
            coord = (
                f"{info.get('ecosystem', '?')}/{info.get('name', '?')}@{info.get('version', '?')}"
            )
            vulns = {v.get("id"): v for v in pkg.get("vulnerabilities", []) or []}
            groups = pkg.get("groups") or [{"ids": list(vulns), "max_severity": None}]
            for group in groups:
                ids = list(group.get("ids") or [])
                aliases: list[str] = []
                for i in ids:
                    aliases.extend((vulns.get(i) or {}).get("aliases") or [])
                advisory = _pick_advisory_id(ids + aliases)
                score_text = group.get("max_severity")
                try:
                    score = float(score_text) if score_text not in (None, "") else None
                except ValueError:
                    score = None
                summary = ""
                for i in ids:
                    summary = (vulns.get(i) or {}).get("summary") or summary
                out.append(
                    Finding(
                        tool="osv",
                        key=f"{coord} :: {advisory}",
                        severity=_severity_from_score(score),
                        path=source,
                        line=None,
                        message=_norm_ws(f"{coord}: {advisory} {summary}", 300),
                        rule=advisory,
                    )
                )
    return out


def parse_gitleaks_json(path: Path, root: Path | None = None) -> list[Finding]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    data = json.loads(text)
    out: list[Finding] = []
    for item in data or []:
        file_ = _rel(item.get("File", ""), root)
        fingerprint = (
            item.get("Fingerprint") or f"{file_}:{item.get('RuleID')}:{item.get('StartLine')}"
        )
        out.append(
            Finding(
                tool="gitleaks",
                key=fingerprint,
                severity="CRITICAL",
                path=file_,
                line=item.get("StartLine"),
                message=_norm_ws(
                    f"{item.get('RuleID')}: {item.get('Description', '')} (secret redacted)", 300
                ),
                rule=item.get("RuleID", ""),
            )
        )
    return out


PARSERS = {
    "opengrep": parse_opengrep_sarif,
    "trivy": parse_trivy_sarif,
    "osv": parse_osv_json,
    "gitleaks": parse_gitleaks_json,
}


# --------------------------------------------------------------------------- baseline


def read_baseline(path: Path) -> set[str] | None:
    if not path.is_file():
        return None
    keys: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        keys.add(line)
    return keys


def render_baseline(
    tool: str, tool_version: str, keys: Iterable[str], commit: str, run_url: str
) -> str:
    header = [
        f"# security/baseline/{tool}.txt -- thyn-ai security toolchain baseline",
        f"# tool: {tool} {tool_version}",
        f"# {HEADER_MARKER} -- never from a laptop. Regenerate only through the security",
        "# workflow's workflow_dispatch with measure_baseline=true; the run below is the evidence.",
        f"# commit: {commit}",
        f"# run: {run_url}",
        "# Every key here is known debt: reported, not fatal. Anything NOT listed fails the gate.",
        "# This file may only shrink. Remove a line when the finding is fixed; never add by hand.",
        "",
    ]
    body = sorted(set(keys))
    return "\n".join(header + body) + "\n"


def write_baseline(path: Path, tool: str, tool_version: str, keys: Iterable[str]) -> None:
    if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        raise RuntimeError(
            "refusing to write a baseline outside GitHub Actions: baselines are measured on CI only"
        )
    commit = os.environ.get("GITHUB_SHA", "unknown")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else "unknown"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_baseline(tool, tool_version, keys, commit, run_url), encoding="utf-8")


# --------------------------------------------------------------------------- evaluate


def evaluate(
    tool: str, findings: Sequence[Finding], baseline: set[str] | None, mode: str
) -> GateResult:
    observed = {f.key for f in findings}
    if baseline is None:
        new = [f for f in findings if f.blocking]
        low = sum(1 for f in findings if not f.blocking)
        return GateResult(tool, mode, False, new, [], [], low)
    new: list[Finding] = []
    known: list[Finding] = []
    low = 0
    for f in findings:
        if f.key in baseline:
            known.append(f)
        elif f.blocking:
            new.append(f)
        else:
            low += 1
    fixed = sorted(baseline - observed)
    return GateResult(tool, mode, True, new, known, fixed, low)


# --------------------------------------------------------------------------- reporting


def _gh_escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def annotate(result: GateResult, stream=None) -> None:
    """Print findings as GitHub workflow commands on Actions, plain text elsewhere."""
    stream = stream or sys.stdout
    on_actions = os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
    fatal = result.exit_code != 0
    for f in result.new:
        level = "error" if (fatal and f.blocking) else "warning"
        if on_actions:
            loc = f"file={_gh_escape(f.path)}" + (f",line={f.line}" if f.line else "")
            print(
                f"::{level} {loc},title={_gh_escape(result.tool)} {f.severity} "
                f"{_gh_escape(f.rule)}::{_gh_escape(f.message)}",
                file=stream,
            )
        else:
            where = f"{f.path}:{f.line}" if f.line else f.path
            print(
                f"[{result.tool}] NEW {f.severity:<8} {where}  {f.rule}\n    {f.message}",
                file=stream,
            )
    if result.known and not on_actions:
        print(f"[{result.tool}] {len(result.known)} baselined finding(s) suppressed", file=stream)
    if result.fixed:
        print(
            f"[{result.tool}] {len(result.fixed)} baseline "
            f"entr{'y' if len(result.fixed) == 1 else 'ies'} no longer observed "
            f"-- shrink security/baseline/{result.tool}.txt:",
            file=stream,
        )
        for k in result.fixed[:20]:
            print(f"    - {k}", file=stream)
    print(f"[{result.tool}] {result.summary}", file=stream)


def markdown_summary(results: Sequence[GateResult]) -> str:
    lines = [
        "| tool | mode | new (blocking) | known | fixed | below threshold |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        state = "advisory" if (r.mode != "ratchet" or not r.baseline_present) else "ratchet"
        blocking = sum(1 for f in r.new if f.blocking)
        lines.append(
            f"| {r.tool} | {state} | {len(r.new)} ({blocking}) | "
            f"{len(r.known) if r.baseline_present else '—'} | {len(r.fixed)} | {r.ignored_low} |"
        )
    return "\n".join(lines) + "\n"
