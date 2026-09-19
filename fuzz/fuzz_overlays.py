"""Fuzz the Opengrep overlay resolver (``data/opengrep-overlays.json`` -> rule packs).

Property: for any overlays mapping, :func:`thyn_security_toolchain.hooks.resolve_overlay`
either raises :class:`~thyn_security_toolchain.hooks.ScanError` or returns two lists of
strings with no duplicates, where every pack and excluded rule comes from an overlay reachable
through ``extends`` from the requested one, parents contribute before children, an ``extends``
cycle terminates, and a second call returns the same answer. Nothing else may escape -- not the
``KeyError`` of an unknown parent, not a bare string iterated character by character.

The resolver reads overlays through ``hooks.load_overlays``; the harness swaps that function
for one returning the generated mapping, the same seam the unit tests use.

Run: ``python fuzz/fuzz_overlays.py fuzz/corpus/overlays -max_total_time=60``
"""

from __future__ import annotations

import json
import sys
from typing import Any

from _support import SeedProvider, check, json_value, run_main, text

from thyn_security_toolchain import hooks

SHIPPED = json.loads(hooks.OVERLAYS_PATH.read_text(encoding="utf-8"))["overlays"]
NAMES = ("base", "python", "javascript", "site", "python-uv", "python-javascript", "a", "b", "c")
FIELDS = ("extends", "packs", "exclude_rules")


def _generate(fdp: Any) -> dict[str, Any]:
    if fdp.ConsumeBool():
        return SHIPPED
    overlays: dict[str, Any] = {}
    for _ in range(fdp.ConsumeIntInRange(0, 6)):
        name = fdp.PickValueInList(NAMES) if fdp.ConsumeBool() else text(fdp, 8)
        if fdp.ConsumeIntInRange(0, 7) == 0:
            overlays[name] = json_value(fdp, FIELDS, depth=2)  # a spec of the wrong shape
            continue
        spec: dict[str, Any] = {}
        for field in FIELDS:
            if fdp.ConsumeBool():
                continue
            if fdp.ConsumeIntInRange(0, 5) == 0:
                spec[field] = json_value(fdp, FIELDS, depth=1)  # wrong type on purpose
            else:
                spec[field] = [
                    fdp.PickValueInList(NAMES) if field == "extends" else text(fdp, 12)
                    for _ in range(fdp.ConsumeIntInRange(0, 3))
                ]
        overlays[name] = spec
    return overlays


def _reachable(overlays: dict[str, Any], start: str) -> list[str]:
    """Overlays reachable from *start* through well-formed ``extends`` lists, parents first."""
    order: list[str] = []
    seen: set[str] = set()

    def visit(name: str) -> None:
        if name in seen or name not in overlays:
            return
        seen.add(name)
        spec = overlays[name]
        parents = spec.get("extends") if isinstance(spec, dict) else None
        for parent in parents if isinstance(parents, list) else []:
            if isinstance(parent, str):
                visit(parent)
        order.append(name)

    visit(start)
    return order


def _declared(overlays: dict[str, Any], names: list[str], field: str) -> list[str]:
    out: list[str] = []
    for name in names:
        spec = overlays[name]
        values = spec.get(field) if isinstance(spec, dict) else None
        out.extend(v for v in (values if isinstance(values, list) else []) if isinstance(v, str))
    return out


def resolve(overlays: dict[str, Any], name: str) -> None:
    original = hooks.load_overlays
    hooks.load_overlays = lambda: overlays
    try:
        try:
            packs, excludes = hooks.resolve_overlay(name)
        except hooks.ScanError:
            return
        for label, values in (("packs", packs), ("exclude_rules", excludes)):
            check(all(isinstance(v, str) for v in values), f"{label}: non-string entry")
            check(len(values) == len(set(values)), f"{label}: duplicate entry")
        chain = _reachable(overlays, name)
        declared_packs = _declared(overlays, chain, "packs")
        check(set(packs) <= set(declared_packs), "a pack came from outside the extends chain")
        check(set(packs) == set(declared_packs), "a declared pack was dropped")
        declared_excludes = _declared(overlays, chain, "exclude_rules")
        check(set(excludes) == set(declared_excludes), "exclude_rules differ from the chain")
        # Parents first: the first occurrence of each pack follows the chain order.
        first_seen = []
        for pack in declared_packs:
            if pack not in first_seen:
                first_seen.append(pack)
        check(packs == first_seen, "packs are not in parents-first order")
        check((packs, excludes) == hooks.resolve_overlay(name), "resolution is not repeatable")
    finally:
        hooks.load_overlays = original


def test_one_input(data: bytes, provider: type = SeedProvider) -> None:
    try:
        raw = json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError):
        raw = None  # unparsable bytes (or nested past the stack): nothing more to check
    if isinstance(raw, dict):
        overlays = raw.get("overlays", raw)
        if isinstance(overlays, dict):
            for name in list(overlays)[:8]:
                if isinstance(name, str):
                    resolve(overlays, name)

    fdp = provider(data)
    overlays = _generate(fdp)
    name = fdp.PickValueInList(list(overlays) or NAMES) if fdp.ConsumeBool() else text(fdp, 8)
    resolve(overlays, name)


def main(argv: list[str]) -> None:
    run_main(argv, test_one_input)


if __name__ == "__main__":
    main(sys.argv)
