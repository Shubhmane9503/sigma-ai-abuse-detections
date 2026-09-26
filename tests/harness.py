"""Shared helpers for the rule test suite.

Single-event rules are converted with pySigma-backend-golangexpr and replayed over NDJSON
samples with SigmaHQ's json_matcher. Correlation rules are converted with
pySigma-backend-sqlite and evaluated in an in-memory SQLite database (see docs/testing.md).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import yaml
from sigma.backends.golangexpr import GolangExprBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType
from sigma.rule import SigmaRule

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
FILTERS_DIR = ROOT / "filters"
DATA_DIR = ROOT / "tests" / "data"
SNAPSHOT_DIR = ROOT / "tests" / "snapshots"
PIPELINES_DIR = ROOT / "pipelines"

SAMPLE_KINDS = ("positive", "negative", "allowlisted")

# Event timestamp field per log source, used by the windowed correlation check.
TIMESTAMP_FIELDS = {
    ("aws", "cloudtrail"): "eventTime",
}


@dataclass(frozen=True)
class RuleCase:
    """A rule file together with its allowlist filter and sample directory."""

    path: Path

    @property
    def stem(self) -> str:
        return self.path.stem

    @property
    def filter_path(self) -> Path:
        """The rule's allowlist hook (every rule has one)."""
        return FILTERS_DIR / f"{self.stem}_allowlist.yml"

    @property
    def filter_paths(self) -> list[Path]:
        """All filters for the rule: the allowlist plus optional extras such as <stem>_tokens.yml."""
        extras = sorted(p for p in FILTERS_DIR.glob(f"{self.stem}_*.yml") if p != self.filter_path)
        return [self.filter_path, *extras]

    @property
    def data_dir(self) -> Path:
        return DATA_DIR / self.stem

    def sample(self, kind: str) -> Path:
        return self.data_dir / f"{kind}.ndjson"

    def collection(self, with_filter: bool = True) -> SigmaCollection:
        paths = [self.path]
        if with_filter:
            paths.extend(self.filter_paths)
        collection = SigmaCollection.load_ruleset(paths)
        collection.resolve_rule_references()
        return collection

    def base_collection(self, with_filter: bool = True) -> SigmaCollection:
        """The rule file without its correlation rule(s), plus the filter.

        Backends suppress output for rules that a correlation references, so the base
        rules are converted on their own to get their per-event query.
        """
        documents = [doc for doc in yaml.safe_load_all(self.path.read_text(encoding="utf-8")) if doc]
        documents = [doc for doc in documents if "correlation" not in doc]
        if with_filter:
            documents.extend(yaml.safe_load(p.read_text(encoding="utf-8")) for p in self.filter_paths)
        collection = SigmaCollection.from_dicts(documents)
        collection.resolve_rule_references()
        return collection

    @property
    def is_correlation(self) -> bool:
        return any(isinstance(rule, SigmaCorrelationRule) for rule in self.collection(with_filter=False))

    def __str__(self) -> str:  # used by pytest ids
        return self.stem


def rule_cases() -> list[RuleCase]:
    return [RuleCase(path) for path in sorted(RULES_DIR.rglob("*.yml"))]


# ---------------------------------------------------------------------------
# NDJSON handling


def normalize_ndjson(raw: bytes) -> bytes:
    """Prepare NDJSON for json_matcher v0.0.2.

    json_matcher splits its input on "\\n" and parses every piece, so a trailing newline
    (which almost every tool writes) or a blank line makes it fail on an empty document.
    CRLF line endings are normalised too.
    """
    lines = raw.replace(b"\r\n", b"\n").split(b"\n")
    return b"\n".join(line for line in lines if line.strip())


def load_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in normalize_ndjson(path.read_bytes()).split(b"\n") if line]


def flatten(event: dict, prefix: str = "") -> dict:
    """Flatten nested objects into dotted keys, the way Sigma addresses nested fields."""
    flat = {}
    for key, value in event.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(flatten(value, f"{name}."))
        else:
            flat[name] = value
    return flat


# ---------------------------------------------------------------------------
# Single-event replay: golang_expr + json_matcher


class ReplayBackend(GolangExprBackend):
    """golang_expr backend that can address field names expr cannot parse.

    The upstream backend emits field names bare, so a Sigma field such as "cs-host" becomes
    the expression `cs - host`. Such names are emitted as `$env["cs-host"]` instead.
    Dotted names keep the backend's nested `a?.b` form.
    """

    # Upstream emits `{field} in $env`, which is wrong for nested fields. `?.` access is
    # nil-safe, so compare against nil instead.
    field_exists_expression = "{field} != nil"
    field_not_exists_expression = "{field} == nil"

    def escape_and_quote_field(self, field_name: str) -> str:
        if re.fullmatch(r"[A-Za-z_][\w.]*", field_name):
            return super().escape_and_quote_field(field_name)
        return '$env["' + field_name.replace("\\", "\\\\").replace('"', '\\"') + '"]'


def to_golang_expr(collection: SigmaCollection) -> str:
    queries = ReplayBackend().convert(collection)
    if len(queries) != 1:
        raise AssertionError(f"expected exactly one golang_expr query, got {len(queries)}")
    return queries[0]


def json_matcher_path() -> str:
    candidates = [
        os.environ.get("JSON_MATCHER"),
        str(ROOT / ".venv" / "bin" / "json_matcher"),
        shutil.which("json_matcher"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise RuntimeError("json_matcher not found: run `make setup` or set JSON_MATCHER")


def run_json_matcher(expression: str, events: bytes) -> list[bool]:
    """Evaluate a golang_expr expression against NDJSON content, one result per event."""
    with tempfile.NamedTemporaryFile("wb", suffix=".ndjson", delete=False) as handle:
        handle.write(normalize_ndjson(events))
        path = handle.name
    try:
        result = subprocess.run(
            [json_matcher_path(), "--test-type", "ndjson", "--event", path, "--expr", expression],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        os.unlink(path)
    if result.returncode != 0:
        raise RuntimeError(f"json_matcher failed: {result.stderr.strip() or result.stdout.strip()}")
    matches = []
    for line in result.stdout.splitlines():
        found = re.fullmatch(r"Line (\d+): (MATCH|NO-MATCH)", line.strip())
        if found:
            matches.append(found.group(2) == "MATCH")
    return matches


def replay(case: RuleCase, kind: str, with_filter: bool = True) -> list[bool]:
    return run_json_matcher(to_golang_expr(case.collection(with_filter)), case.sample(kind).read_bytes())


# ---------------------------------------------------------------------------
# Correlation: SQLite


class SqlReplayBackend(sqliteBackend):
    """SQLite backend with a NULL-correct `|exists`.

    Upstream emits `field = field`, which is NULL (not false) for a missing field, so
    `not (field|exists and ...)` still drops the event. `IS NOT NULL` is what ES|QL emits
    (`is not null`) and gives the intended two-valued result.
    """

    field_exists_expression = "{field} IS NOT NULL"
    field_not_exists_expression = "{field} IS NULL"


def _sqlite_backend() -> sqliteBackend:
    return SqlReplayBackend()


def _load_table(events: list[dict]) -> sqlite3.Connection:
    """Load events into table `logs`. Columns are case-insensitive, like Sigma matching."""
    rows = [flatten(event) for event in events]
    columns = sorted({key for row in rows for key in row})
    conn = sqlite3.connect(":memory:")
    column_sql = ", ".join(f'"{c}" TEXT COLLATE NOCASE' for c in columns)
    conn.execute(f"CREATE TABLE logs (_row INTEGER PRIMARY KEY, {column_sql})")
    for index, row in enumerate(rows):
        names = ", ".join(f'"{c}"' for c in row)
        marks = ", ".join("?" for _ in row)
        values = [json.dumps(v) if isinstance(v, (list, dict)) else v for v in row.values()]
        conn.execute(f"INSERT INTO logs (_row, {names}) VALUES (?, {marks})", [index, *values])
    return conn


def _run_sql(conn: sqlite3.Connection, sql: str) -> list[sqlite3.Row]:
    """Run SQL, adding empty columns for fields the samples do not contain."""
    sql = sql.replace("<TABLE_NAME>", "logs")
    while True:
        try:
            conn.row_factory = sqlite3.Row
            return conn.execute(sql).fetchall()
        except sqlite3.OperationalError as error:
            missing = re.match(r"no such column: (.+)", str(error))
            if not missing:
                raise
            conn.execute(f'ALTER TABLE logs ADD COLUMN "{missing.group(1).strip("`")}" TEXT COLLATE NOCASE')


def sqlite_replay(case: RuleCase, kind: str, with_filter: bool = True) -> list[bool]:
    """Evaluate a single-event rule with the SQLite backend: one result per event.

    This second engine has SQL NULL semantics: a missing field makes a comparison
    unknown, so a `NOT field = 'x'` allowlist silently drops events that lack the field.
    ES|QL behaves the same way, while golang_expr treats a missing field as "".
    Agreement between both engines on the samples guards against filters that
    only work when optional fields are present.
    """
    events = load_events(case.sample(kind))
    conn = _load_table(events)
    matched = {row["_row"] for query in _sqlite_backend().convert(case.collection(with_filter)) for row in _run_sql(conn, query)}
    return [index in matched for index in range(len(events))]


def _correlation_parts(collection: SigmaCollection) -> tuple[SigmaCorrelationRule, list[SigmaRule]]:
    correlations = [rule for rule in collection if isinstance(rule, SigmaCorrelationRule)]
    if len(correlations) != 1:
        raise AssertionError("expected exactly one correlation rule per file")
    correlation = correlations[0]
    bases = [reference.rule for reference in correlation.rules]
    return correlation, bases


def backend_correlation_rows(case: RuleCase, kind: str, with_filter: bool = True) -> list[sqlite3.Row]:
    """Rows returned by the SQL the SQLite backend generates for the correlation, unmodified."""
    queries = _sqlite_backend().convert(case.collection(with_filter))
    conn = _load_table(load_events(case.sample(kind)))
    return [row for query in queries for row in _run_sql(conn, query)]


def windowed_correlation_alerts(
    case: RuleCase, kind: str, with_filter: bool = True, ignore_timespan: bool = False
) -> list[dict]:
    """Evaluate the correlation with an explicit sliding time window.

    The base rule(s) are converted by the SQLite backend and run in SQLite, so event
    selection and allowlist filters come from the backend's own SQL. The grouping,
    timespan and threshold come from the parsed correlation rule, and the window is
    applied here because the backend's generated SQL does not apply it.
    With ignore_timespan=True the window is unbounded (used to prove that negative
    samples contain a case only the timespan keeps quiet).
    """
    correlation, bases = _correlation_parts(case.collection(with_filter))
    conn = _load_table(load_events(case.sample(kind)))

    matched: dict[int, sqlite3.Row] = {}
    for query in _sqlite_backend().convert(case.base_collection(with_filter)):
        for row in _run_sql(conn, query):
            matched[row["_row"]] = row

    logsource = (bases[0].logsource.product, bases[0].logsource.service)
    time_field = TIMESTAMP_FIELDS.get(logsource)
    if time_field is None:
        raise AssertionError(f"no timestamp field configured for log source {logsource}")

    span = timedelta.max if ignore_timespan else timedelta(seconds=correlation.timespan.seconds)
    group_by = list(correlation.group_by or [])
    condition = correlation.condition
    threshold_ops = {
        "gte": lambda v, t: v >= t,
        "gt": lambda v, t: v > t,
        "lte": lambda v, t: v <= t,
        "lt": lambda v, t: v < t,
        "eq": lambda v, t: v == t,
        "neq": lambda v, t: v != t,
    }
    op = threshold_ops[condition.op.name.lower()]

    groups: dict[tuple, list[tuple[datetime, sqlite3.Row]]] = {}
    for row in matched.values():
        key = tuple(row[field] for field in group_by)
        stamp = datetime.fromisoformat(str(row[time_field]).replace("Z", "+00:00"))
        groups.setdefault(key, []).append((stamp, row))

    alerts = []
    for key, items in groups.items():
        items.sort(key=lambda item: item[0])
        for start, _ in items:
            window = [row for stamp, row in items if stamp >= start and (ignore_timespan or stamp < start + span)]
            if correlation.type == SigmaCorrelationType.VALUE_COUNT:
                value = len({row[condition.fieldref] for row in window})
            elif correlation.type == SigmaCorrelationType.EVENT_COUNT:
                value = len(window)
            else:
                raise AssertionError(f"correlation type {correlation.type} not supported by the harness")
            if op(value, condition.count):
                alerts.append({"group": dict(zip(group_by, key)), "window_start": start.isoformat(), "value": value})
                break
    return alerts
