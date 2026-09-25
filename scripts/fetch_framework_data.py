#!/usr/bin/env python3
"""Fetch the pinned MITRE ATT&CK and MITRE ATLAS releases and write compact extracts.

The full ATT&CK STIX bundle is ~50 MB, too large to vendor. This script downloads the
pinned release files, verifies their SHA-256 checksums and writes small extracts into
mappings/. The extracts are committed; CI re-runs this script with --check to prove that
they still match the pinned upstream files.

Extracts:
  mappings/attack-v19.2/enterprise-attack-19.2.min.json
      A valid STIX bundle holding only the fields pySigma's tag validator and the mapping
      tests read (IDs, names, tactic short names, kill chain phases, revoked/deprecated).
  mappings/atlas-2026.09/atlas-2026.09.min.json
      ATLAS tactic and technique IDs with names.

Usage:
  python scripts/fetch_framework_data.py          # download and (re)write the extracts
  python scripts/fetch_framework_data.py --check  # download and fail if extracts differ
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

ATTACK = {
    "version": "19.2",
    "url": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack-19.2.json"
    ),
    "sha256": "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
    "out": ROOT / "mappings" / "attack-v19.2" / "enterprise-attack-19.2.min.json",
}

ATLAS = {
    "version": "2026.09",
    "url": (
        "https://raw.githubusercontent.com/mitre-atlas/atlas-data/"
        "3259f388d19cbcca11bacf12a0ef97f4198f711b/dist/v6/ATLAS-2026.09.yaml"
    ),
    "sha256": "935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688",
    "out": ROOT / "mappings" / "atlas-2026.09" / "atlas-2026.09.min.json",
}

# STIX object types pySigma reads, and the fields kept for each object.
ATTACK_TYPES = {
    "x-mitre-collection",
    "x-mitre-tactic",
    "attack-pattern",
    "intrusion-set",
    "malware",
    "tool",
    "x-mitre-data-source",
    "course-of-action",
}
ATTACK_FIELDS = (
    "type",
    "id",
    "name",
    "revoked",
    "x_mitre_deprecated",
    "x_mitre_shortname",
    "x_mitre_version",
    "kill_chain_phases",
)


def download(url: str, sha256: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "sigma-ai-abuse-detections"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != sha256:
        raise SystemExit(f"checksum mismatch for {url}: expected {sha256}, got {digest}")
    return data


def extract_attack(raw: bytes) -> dict:
    bundle = json.loads(raw)
    objects = []
    for obj in bundle["objects"]:
        if obj.get("type") not in ATTACK_TYPES:
            continue
        slim = {key: obj[key] for key in ATTACK_FIELDS if key in obj}
        refs = [
            {"source_name": ref["source_name"], "external_id": ref["external_id"]}
            for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack" and "external_id" in ref
        ]
        if refs:
            slim["external_references"] = refs
        elif obj.get("type") != "x-mitre-collection":
            continue
        objects.append(slim)
    objects.sort(key=lambda o: (o["type"], o.get("external_references", [{}])[0].get("external_id", ""), o["id"]))
    return {
        "type": "bundle",
        "id": bundle["id"],
        "x_extract_of": {"url": ATTACK["url"], "sha256": ATTACK["sha256"], "version": ATTACK["version"]},
        "objects": objects,
    }


def extract_atlas(raw: bytes) -> dict:
    data = yaml.safe_load(raw)
    version = data["collection"]["version"]
    if version != ATLAS["version"]:
        raise SystemExit(f"unexpected ATLAS version {version}")
    return {
        "x_extract_of": {"url": ATLAS["url"], "sha256": ATLAS["sha256"], "version": version},
        "tactics": {key: {"name": value["name"]} for key, value in sorted(data["tactics"].items())},
        "techniques": {key: {"name": value["name"]} for key, value in sorted(data["techniques"].items())},
    }


def render(obj: dict) -> str:
    return json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="fail if committed extracts differ from upstream")
    args = parser.parse_args()

    outputs = {
        ATTACK["out"]: render(extract_attack(download(ATTACK["url"], ATTACK["sha256"]))),
        ATLAS["out"]: render(extract_atlas(download(ATLAS["url"], ATLAS["sha256"]))),
    }

    stale = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if args.check:
            if current != content:
                stale.append(path)
        elif current != content:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
        else:
            print(f"up to date {path.relative_to(ROOT)}")

    if stale:
        for path in stale:
            print(f"stale extract: {path.relative_to(ROOT)} (run: python scripts/fetch_framework_data.py)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
