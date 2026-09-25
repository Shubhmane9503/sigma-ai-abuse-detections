#!/usr/bin/env python3
"""Run `sigma check` against the pinned ATT&CK v19.2 data instead of the latest upstream.

pySigma's tag validator downloads the newest ATT&CK release from GitHub by default,
which makes `sigma check` results change whenever MITRE publishes and fails offline.
This wrapper points pySigma at the committed extract and uses a repository-local cache,
then hands all arguments to the regular sigma-cli entry point.

Usage: python scripts/sigma_check.py [sigma check options] PATH...
"""

import sys
from pathlib import Path

from sigma.data import mitre_attack

ROOT = Path(__file__).resolve().parent.parent
ATTACK_EXTRACT = ROOT / "mappings" / "attack-v19.2" / "enterprise-attack-19.2.min.json"
CACHE_DIR = ROOT / ".cache" / "pysigma-attack-v19.2"


def main() -> None:
    mitre_attack.set_cache_dir(str(CACHE_DIR))
    mitre_attack.set_url(str(ATTACK_EXTRACT))

    from sigma.cli.main import main as sigma_main

    # The D3FEND tag validator downloads D3FEND data on every run. No rule here carries
    # D3FEND tags, so it is excluded rather than left as an unpinned network dependency.
    sys.argv = ["sigma", "check", "--exclude", "d3_fendtag", *sys.argv[1:]]
    sigma_main()


if __name__ == "__main__":
    main()
