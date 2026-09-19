"""Fuzz the scanner-report parsers and the SARIF rewriters (``gate.py``).

Every report a scanner writes -- Opengrep SARIF, Trivy SARIF, osv-scanner JSON, Gitleaks JSON
-- is read by one parser in :data:`thyn_security_toolchain.gate.PARSERS`. Properties, for any
bytes on disk and for schema-shaped JSON with deliberate type confusion:

* A parser returns a list of :class:`~thyn_security_toolchain.gate.Finding` or raises
  :class:`ValueError` (:class:`~thyn_security_toolchain.gate.ReportError` for a wrong shape or
  for nesting deeper than the interpreter parses, ``JSONDecodeError`` for bad JSON). Nothing
  else escapes.
* Every finding has the parser's tool name, a non-empty string key, a known severity, a string
  path and a ``line`` that is ``None`` or an ``int``. Trivy keys are unique (the parser
  deduplicates per check and file). Parsing the same file twice yields identical keys.
* Opengrep keys are line-number independent: rewriting every ``startLine`` leaves them
  unchanged. ``normalize_opengrep_rule_id`` and ``_norm_ws`` are idempotent.
* ``demote_low_confidence_levels`` and ``drop_audit_results`` are idempotent: a second pass
  changes nothing and returns 0, the file stays valid JSON, and after a drop no low-confidence
  result remains.

Run: ``python fuzz/fuzz_reports.py fuzz/corpus/reports -max_total_time=60``
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _support import SeedProvider, check, json_value, run_main, text  # noqa: E402

from thyn_security_toolchain import gate  # noqa: E402

WORK = Path(tempfile.mkdtemp(prefix="thyn-sec-fuzz-reports-"))
REPORT = WORK / "report.json"
ROOT = WORK / "repo"
ROOT.mkdir()

SARIF_KEYS = (
    "runs",
    "tool",
    "driver",
    "rules",
    "id",
    "properties",
    "tags",
    "security-severity",
    "shortDescription",
    "text",
    "defaultConfiguration",
    "level",
    "results",
    "ruleId",
    "message",
    "locations",
    "physicalLocation",
    "artifactLocation",
    "uri",
    "region",
    "startLine",
    "snippet",
)
OSV_KEYS = (
    "results",
    "source",
    "path",
    "packages",
    "package",
    "ecosystem",
    "name",
    "version",
    "vulnerabilities",
    "id",
    "aliases",
    "summary",
    "groups",
    "ids",
    "max_severity",
)
GITLEAKS_KEYS = ("File", "Fingerprint", "RuleID", "StartLine", "Description", "Secret")
TOOLS = ("opengrep", "trivy", "osv", "gitleaks")
KEYS = {"opengrep": SARIF_KEYS, "trivy": SARIF_KEYS, "osv": OSV_KEYS, "gitleaks": GITLEAKS_KEYS}


def _rule(fdp: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {"id": text(fdp, 24)}
    if fdp.ConsumeBool():
        rule["properties"] = {
            "tags": [fdp.PickValueInList(["LOW CONFIDENCE", "security", "audit", 3])],
            "security-severity": fdp.PickValueInList(["9.8", "7.0", "4.0", "0.1", "x", None, 5]),
        }
    if fdp.ConsumeBool():
        rule["defaultConfiguration"] = {"level": fdp.PickValueInList(["error", "warning", None])}
    if fdp.ConsumeBool():
        rule["shortDescription"] = {"text": text(fdp, 30)}
    return rule


def _result(fdp: Any, rule_ids: list[str]) -> dict[str, Any]:
    res: dict[str, Any] = {}
    if fdp.ConsumeBool():
        res["ruleId"] = fdp.PickValueInList(rule_ids) if rule_ids else text(fdp, 24)
    if fdp.ConsumeBool():
        res["level"] = fdp.PickValueInList(["error", "warning", "note", "none", 1])
    if fdp.ConsumeBool():
        res["message"] = {"text": text(fdp, 60)} if fdp.ConsumeBool() else text(fdp, 10)
    if fdp.ConsumeBool():
        region: dict[str, Any] = {"startLine": fdp.PickValueInList([1, 42, 0, -1, "3", None])}
        if fdp.ConsumeBool():
            region["snippet"] = {"text": text(fdp, 60)}
        res["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": text(fdp, 40)}, "region": region}}
        ]
    return res


def _sarif(fdp: Any) -> Any:
    rules = [_rule(fdp) for _ in range(fdp.ConsumeIntInRange(0, 3))]
    rule_ids = [r["id"] for r in rules if isinstance(r.get("id"), str)]
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "fuzz", "rules": rules}},
                "results": [_result(fdp, rule_ids) for _ in range(fdp.ConsumeIntInRange(0, 4))],
            }
            for _ in range(fdp.ConsumeIntInRange(0, 2))
        ],
    }


def _osv(fdp: Any) -> Any:
    def vuln() -> dict[str, Any]:
        return {
            "id": text(fdp, 20),
            "aliases": [text(fdp, 20) for _ in range(fdp.ConsumeIntInRange(0, 2))],
            "summary": text(fdp, 40),
        }

    def package() -> dict[str, Any]:
        vulns = [vuln() for _ in range(fdp.ConsumeIntInRange(0, 3))]
        pkg: dict[str, Any] = {
            "package": {"ecosystem": text(fdp, 8), "name": text(fdp, 12), "version": text(fdp, 8)},
            "vulnerabilities": vulns,
        }
        if fdp.ConsumeBool():
            pkg["groups"] = [
                {
                    "ids": [v["id"] for v in vulns[: fdp.ConsumeIntInRange(0, len(vulns))]],
                    "max_severity": fdp.PickValueInList(["9.8", "7.0", "4.0", "", None, "x", 1]),
                }
                for _ in range(fdp.ConsumeIntInRange(0, 2))
            ]
        return pkg

    return {
        "results": [
            {
                "source": {"path": text(fdp, 40)},
                "packages": [package() for _ in range(fdp.ConsumeIntInRange(0, 3))],
            }
            for _ in range(fdp.ConsumeIntInRange(0, 2))
        ]
    }


def _gitleaks(fdp: Any) -> Any:
    return [
        {
            "File": text(fdp, 40),
            "RuleID": text(fdp, 20),
            "StartLine": fdp.PickValueInList([1, 9, 0, "2", None]),
            "Description": text(fdp, 30),
            "Fingerprint": text(fdp, 40) if fdp.ConsumeBool() else "",
        }
        for _ in range(fdp.ConsumeIntInRange(0, 3))
    ]


GENERATORS = {"opengrep": _sarif, "trivy": _sarif, "osv": _osv, "gitleaks": _gitleaks}


def _write(payload: Any, as_text: bool = False) -> None:
    if as_text:
        REPORT.write_bytes(payload)
    else:
        REPORT.write_text(json.dumps(payload), encoding="utf-8")


def parse(tool: str, root: Path | None) -> list[gate.Finding] | None:
    """Run one parser; return its findings or None when it raised the documented error."""
    try:
        findings = gate.PARSERS[tool](REPORT, root)
    except ValueError:
        return None
    for f in findings:
        check(f.tool in {"opengrep", "trivy", "osv", "gitleaks"}, f"{tool}: bad tool {f.tool!r}")
        check(isinstance(f.key, str) and f.key != "", f"{tool}: empty or non-string key")
        check(f.severity in gate.SEVERITY_ORDER, f"{tool}: unknown severity {f.severity!r}")
        check(isinstance(f.path, str), f"{tool}: non-string path")
        check(f.line is None or isinstance(f.line, int), f"{tool}: line {f.line!r}")
        check(isinstance(f.message, str) and isinstance(f.rule, str), f"{tool}: message/rule")
        check(gate._norm_ws(f.message, 300) == f.message, f"{tool}: message not normalised")
        check(f.key == f.key.strip(), f"{tool}: key has surrounding whitespace: {f.key!r}")
    if tool == "trivy":
        keys = [f.key for f in findings]
        check(len(keys) == len(set(keys)), "trivy keys must be unique after dedup")
    again = gate.PARSERS[tool](REPORT, root)
    check([f.key for f in again] == [f.key for f in findings], f"{tool}: keys not repeatable")
    return findings


def _renumber(doc: Any, line: int) -> None:
    if isinstance(doc, dict):
        if "startLine" in doc:
            doc["startLine"] = line
        for v in doc.values():
            _renumber(v, line)
    elif isinstance(doc, list):
        for v in doc:
            _renumber(v, line)


def exercise_opengrep(doc: Any, root: Path | None) -> None:
    _write(doc)
    findings = parse("opengrep", root)
    if findings is None:
        return
    for f in findings:
        check(
            gate.normalize_opengrep_rule_id(f.rule) == f.rule,
            "normalize_opengrep_rule_id is not idempotent on an emitted rule id",
        )
    _renumber(doc, 4242)
    _write(doc)
    moved = gate.PARSERS["opengrep"](REPORT, root)
    check(
        [f.key for f in moved] == [f.key for f in findings],
        "opengrep keys changed when every startLine moved",
    )


def exercise_rewriters(doc: Any) -> None:
    for rewrite in (gate.demote_low_confidence_levels, gate.drop_audit_results):
        _write(doc)
        try:
            rewrite(REPORT)
        except ValueError:
            return
        first = REPORT.read_bytes()
        json.loads(first)
        check(rewrite(REPORT) == 0, f"{rewrite.__name__}: second pass still changed results")
        check(REPORT.read_bytes() == first, f"{rewrite.__name__}: second pass rewrote the file")
    findings = parse("opengrep", None)
    if findings is None:
        return
    data = json.loads(REPORT.read_text(encoding="utf-8"))
    for run in data.get("runs", []) or []:
        rules = {
            r.get("id"): r
            for r in ((run.get("tool") or {}).get("driver") or {}).get("rules", []) or []
        }
        for res in run.get("results", []) or []:
            rid = res.get("ruleId", "")
            check(
                not gate._is_low_confidence_rule(rid, rules.get(rid, {})),
                "a low-confidence result survived drop_audit_results",
            )


def test_one_input(data: bytes, provider: type = SeedProvider) -> None:
    _write(data, as_text=True)
    for tool in TOOLS:
        parse(tool, None)
    try:
        raw = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        raw = None  # unparsable bytes (or nested past the stack): the parsers raised ValueError
    if raw is not None:
        exercise_rewriters(raw)

    fdp = provider(data)
    tool = fdp.PickValueInList(TOOLS)
    doc = GENERATORS[tool](fdp) if fdp.ConsumeIntInRange(0, 4) else json_value(fdp, KEYS[tool], 4)
    root = ROOT if fdp.ConsumeBool() else None
    if tool == "opengrep":
        exercise_opengrep(doc, root)
        exercise_rewriters(doc)
    else:
        _write(doc)
        parse(tool, root)

    for sample in (text(fdp, 60), fdp.ConsumeUnicodeNoSurrogates(20)):
        once = gate.normalize_opengrep_rule_id(sample)
        check(gate.normalize_opengrep_rule_id(once) == once, "rule-id normalisation")
        norm = gate._norm_ws(sample)
        check(gate._norm_ws(norm) == norm, "_norm_ws is not idempotent")
        check(len(norm) <= 100, "_norm_ws exceeded its limit")
        rel = gate._rel(sample, root)
        check(isinstance(rel, str), "_rel must return a string")


def main(argv: list[str]) -> None:
    run_main(argv, test_one_input)


if __name__ == "__main__":
    main(sys.argv)
