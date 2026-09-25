#!/usr/bin/env python3
"""Validate every rule's ATT&CK tags and ATLAS IDs against the pinned framework data.

Checks, per rule document (base and correlation rules included):
  - every attack.tNNNN[.NNN] tag exists in ATT&CK v19.2 and is not revoked or deprecated
  - every attack.<tactic> tag is a tactic short name in ATT&CK v19.2
  - every technique tag belongs to at least one of the rule's tactic tags (when it has any)
  - the rule has at least one ATLAS ID in its `atlas:` field
  - every ATLAS ID exists in ATLAS 2026.09 (ATLAS marks no deprecations: removed IDs are absent)
  - a rule without ATT&CK tags says so in its description ("No ATT&CK mapping")

Prints one line per rule and exits non-zero if any check fails.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
ATTACK_EXTRACT = ROOT / "mappings" / "attack-v19.2" / "enterprise-attack-19.2.min.json"
ATLAS_EXTRACT = ROOT / "mappings" / "atlas-2026.09" / "atlas-2026.09.min.json"

TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


@dataclass
class AttackData:
    techniques: dict[str, dict]  # "T1552.001" -> {name, revoked, deprecated, tactics}
    tactics: dict[str, str]  # short name -> "TA0006"


@lru_cache(maxsize=None)
def attack_data() -> AttackData:
    bundle = json.loads(ATTACK_EXTRACT.read_text(encoding="utf-8"))
    techniques, tactics = {}, {}
    for obj in bundle["objects"]:
        refs = obj.get("external_references", [])
        if not refs:
            continue
        external_id = refs[0]["external_id"]
        if obj["type"] == "attack-pattern":
            techniques[external_id] = {
                "name": obj["name"],
                "revoked": bool(obj.get("revoked")),
                "deprecated": bool(obj.get("x_mitre_deprecated")),
                "tactics": {
                    phase["phase_name"]
                    for phase in obj.get("kill_chain_phases", [])
                    if phase.get("kill_chain_name") == "mitre-attack"
                },
            }
        elif obj["type"] == "x-mitre-tactic" and not obj.get("revoked") and not obj.get("x_mitre_deprecated"):
            tactics[obj["x_mitre_shortname"]] = external_id
    return AttackData(techniques, tactics)


@lru_cache(maxsize=None)
def atlas_techniques() -> dict[str, dict]:
    return json.loads(ATLAS_EXTRACT.read_text(encoding="utf-8"))["techniques"]


@dataclass
class RuleMapping:
    path: Path
    title: str
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    atlas: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def rule_documents() -> list[tuple[Path, dict]]:
    documents = []
    for path in sorted(RULES_DIR.rglob("*.yml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if doc:
                documents.append((path, doc))
    return documents


def validate(path: Path, doc: dict) -> RuleMapping:
    data = attack_data()
    result = RuleMapping(path=path, title=doc.get("title", "?"))

    for tag in doc.get("tags", []) or []:
        if not tag.startswith("attack."):
            continue
        technique = TECHNIQUE_TAG.match(tag)
        if technique:
            result.techniques.append(technique.group(1).upper())
        else:
            result.tactics.append(tag.removeprefix("attack."))

    for technique_id in result.techniques:
        technique = data.techniques.get(technique_id)
        if technique is None:
            result.errors.append(f"{technique_id} is not in ATT&CK v19.2")
            continue
        if technique["revoked"] or technique["deprecated"]:
            state = "revoked" if technique["revoked"] else "deprecated"
            result.errors.append(f"{technique_id} ({technique['name']}) is {state} in ATT&CK v19.2")
        if result.tactics and not technique["tactics"] & set(result.tactics):
            result.errors.append(
                f"{technique_id} belongs to {sorted(technique['tactics'])}, none of the rule's tactic tags {result.tactics}"
            )
    for tactic in result.tactics:
        if tactic not in data.tactics:
            result.errors.append(f"attack.{tactic} is not a tactic in ATT&CK v19.2")

    if not result.techniques and not result.tactics:
        if "no att&ck mapping" not in str(doc.get("description", "")).lower():
            result.errors.append("no ATT&CK tags and the description does not say why")

    atlas = doc.get("atlas")
    if not isinstance(atlas, list) or not atlas:
        result.errors.append("missing `atlas:` list")
    else:
        result.atlas = [str(item) for item in atlas]
        for atlas_id in result.atlas:
            if atlas_id not in atlas_techniques():
                result.errors.append(f"{atlas_id} is not in ATLAS 2026.09")
    return result


def validate_all() -> list[RuleMapping]:
    return [validate(path, doc) for path, doc in rule_documents()]


def describe(mapping: RuleMapping) -> str:
    names = [f"{t} {attack_data().techniques.get(t, {}).get('name', '?')}" for t in mapping.techniques]
    atlas = [f"{a} {atlas_techniques().get(a, {}).get('name', '?')}" for a in mapping.atlas]
    return (
        f"{mapping.title}\n"
        f"    ATT&CK: {', '.join(names) or '-'} | tactics: {', '.join(mapping.tactics) or '-'}\n"
        f"    ATLAS:  {', '.join(atlas) or '-'}"
    )


def main() -> int:
    failed = 0
    for mapping in validate_all():
        status = "FAIL" if mapping.errors else "ok  "
        print(f"[{status}] {describe(mapping)}")
        for error in mapping.errors:
            print(f"        error: {error}")
        failed += bool(mapping.errors)
    print(f"\n{failed} rule(s) with mapping errors (ATT&CK v19.2, ATLAS 2026.09)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
