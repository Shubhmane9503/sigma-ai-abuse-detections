"""Conversion snapshots and committed-query drift.

Fresh conversions (Splunk, ES|QL, golang_expr, SQLite) must equal tests/snapshots/, and the
committed queries/ must equal fresh `make convert` output. After an intentional change run
`make snapshots` and review the diff in the pull request.
"""

import pytest

from conversions import QUERY_DIRS, expected_files
from harness import SNAPSHOT_DIR

EXPECTED = expected_files()


@pytest.mark.parametrize("path", sorted(EXPECTED), ids=lambda p: f"{p.parent.name}/{p.name}")
def test_generated_file_is_current(path):
    assert path.is_file(), f"{path.name} is missing: run `make snapshots`"
    assert path.read_text(encoding="utf-8") == EXPECTED[path], f"{path.name} is stale: run `make snapshots` and review the diff"


def test_no_stale_generated_files():
    generated = {p for d in [SNAPSHOT_DIR, *QUERY_DIRS.values()] if d.exists() for p in d.iterdir() if p.is_file()}
    stale = sorted(str(p.name) for p in generated - set(EXPECTED))
    assert not stale, f"generated files without a rule (delete them): {stale}"


def test_coverage_matrix_is_current():
    from coverage_matrix import OUTPUT, render

    assert OUTPUT.is_file() and OUTPUT.read_text(encoding="utf-8") == render(), "docs/coverage.md is stale: run `make matrix`"
