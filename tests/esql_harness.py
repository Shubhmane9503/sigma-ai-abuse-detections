"""Run the committed ES|QL queries against a real Elasticsearch.

Samples are translated to the shape the ES|QL pipelines expect (ECS for CloudTrail, proxy
and endpoint events) using the field mappings and added conditions in pipelines/esql/*.yml
themselves, so the translation cannot drift from the pipelines. Log sources without an
ES|QL pipeline (Azure activity, LLM gateway) are indexed with their raw field names, which
is what their queries use.

Each rule and sample kind gets its own index. All strings are mapped as keyword, and
@timestamp is derived from the log source's timestamp field.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from harness import PIPELINES_DIR, ROOT, RuleCase, flatten, load_events

QUERY_DIR = ROOT / "queries" / "esql"
KNOWN_GAPS_FILE = ROOT / "tests" / "esql_known_gaps.yml"
INDEX_PREFIX = "sigma-esql-test"

# Timestamp source per sample field, in order of preference.
TIMESTAMP_FIELDS = ("eventTime", "TimeGenerated", "timestamp", "UtcTime")


def es_url() -> str | None:
    return os.environ.get("ESQL_TEST_URL")


def known_gaps() -> dict[str, dict[str, str]]:
    return yaml.safe_load(KNOWN_GAPS_FILE.read_text(encoding="utf-8")) or {}


# ---------------------------------------------------------------------------
# Translation driven by pipelines/esql/*.yml


def _logsource_matches(condition: dict, logsource) -> bool:
    return all(getattr(logsource, key, None) == value for key, value in condition.items() if key != "type")


def _applies(item: dict, logsource) -> bool:
    conditions = [c for c in item.get("rule_conditions", []) if c.get("type") == "logsource"]
    if not conditions:
        return True
    matches = [_logsource_matches(c, logsource) for c in conditions]
    return any(matches) if item.get("rule_cond_op") == "or" else all(matches)


def translation_for(case: RuleCase) -> tuple[dict[str, str], dict[str, str]]:
    """(field mapping, added field values) that the ES|QL pipelines apply to this rule."""
    documents = [doc for doc in yaml.safe_load_all(case.path.read_text(encoding="utf-8")) if doc]
    source = next(doc for doc in documents if "logsource" in doc)
    from sigma.rule import SigmaLogSource

    logsource = SigmaLogSource.from_dict(source["logsource"])
    mapping, added = {}, {}
    for path in sorted((PIPELINES_DIR / "esql").glob("*.yml")):
        for item in yaml.safe_load(path.read_text(encoding="utf-8"))["transformations"]:
            if not _applies(item, logsource):
                continue
            if item["type"] == "field_name_mapping":
                mapping.update(item["mapping"])
            elif item["type"] == "add_condition":
                added.update(item["conditions"])
    return mapping, added


def _timestamp(event: dict) -> str | None:
    for name in TIMESTAMP_FIELDS:
        if name in event:
            value = str(event[name]).replace(" ", "T")
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            return stamp.isoformat()
    if "date" in event and "time" in event:  # proxy logs
        return f"{event['date']}T{event['time']}+00:00"
    return None


def translate(case: RuleCase, event: dict) -> dict:
    mapping, added = translation_for(case)
    flat = flatten(event)
    document = {mapping.get(key, key): value for key, value in flat.items()}
    document.update(added)
    stamp = _timestamp(event)
    if stamp:
        document["@timestamp"] = stamp
    return document


# ---------------------------------------------------------------------------
# Elasticsearch access


def _request(method: str, path: str, body: dict | str | None = None) -> dict:
    data = None
    headers = {"Content-Type": "application/json"}
    if isinstance(body, dict):
        data = json.dumps(body).encode()
    elif isinstance(body, str):
        data = body.encode()
        headers["Content-Type"] = "application/x-ndjson"
    request = urllib.request.Request(f"{es_url()}{path}", data=data, method=method, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # always talk to ES directly
    try:
        with opener.open(request, timeout=60) as response:
            return json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        payload = json.loads(error.read() or b"{}")
        raise RuntimeError(f"{method} {path}: {payload.get('error', payload)}") from error


def index_name(case: RuleCase, kind: str) -> str:
    return f"{INDEX_PREFIX}-{case.stem.replace('_', '-')}-{kind}"


def load_index(case: RuleCase, kind: str) -> str:
    """(Re)create the index for one sample file. Document _id is the 0-based line number."""
    name = index_name(case, kind)
    try:
        _request("DELETE", f"/{name}")
    except RuntimeError:
        pass
    _request(
        "PUT",
        f"/{name}",
        {
            "mappings": {
                "dynamic_templates": [
                    {"strings_as_keyword": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}
                ],
                "properties": {"@timestamp": {"type": "date"}},
            }
        },
    )
    lines = []
    for number, event in enumerate(load_events(case.sample(kind))):
        lines.append(json.dumps({"index": {"_index": name, "_id": str(number)}}))
        lines.append(json.dumps(translate(case, event)))
    result = _request("POST", "/_bulk?refresh=true", "\n".join(lines) + "\n")
    if result.get("errors"):
        failed = [item["index"]["error"] for item in result["items"] if "error" in item["index"]]
        raise RuntimeError(f"bulk indexing into {name} failed: {failed[:3]}")
    return name


def committed_query(case: RuleCase) -> str:
    return (QUERY_DIR / f"{case.stem}.esql").read_text(encoding="utf-8").strip()


def retarget(query: str, index: str, time_range: tuple[str, str] | None = None) -> str:
    """Point the query's `from` clause at the test index, optionally limiting @timestamp."""
    query, count = re.subn(r"^from \S+", f"from {index}", query, count=1)
    if count != 1:
        raise AssertionError(f"query does not start with a from clause: {query[:80]}")
    if time_range:
        start, end = time_range
        query = query.replace(
            " | where ",
            f' | where @timestamp >= to_datetime("{start}") and @timestamp < to_datetime("{end}") | where ',
            1,
        )
    return query


def run_query(query: str) -> list[dict]:
    result = _request("POST", "/_query", {"query": query})
    names = [column["name"] for column in result["columns"]]
    return [dict(zip(names, row)) for row in result["values"]]


def matched_lines(case: RuleCase, kind: str) -> list[bool]:
    """Per-event results of a single-event query."""
    index = load_index(case, kind)
    rows = run_query(retarget(committed_query(case), index))
    matched = {int(row["_id"]) for row in rows}
    return [number in matched for number in range(len(load_events(case.sample(kind))))]


def correlation_alert_groups(case: RuleCase, kind: str, timespan: timedelta) -> set[str]:
    """Groups the correlation query alerts on when scheduled with a lookback of `timespan`.

    The shipped query has no time bucket. It is meant to run every few minutes over the last
    `timespan`. This is emulated by running it once per window [t, t + timespan) for every
    event time t in the sample, which covers every distinct set of events a schedule sees.
    """
    index = load_index(case, kind)
    query = committed_query(case)
    groups: set[str] = set()
    for event in load_events(case.sample(kind)):
        start = datetime.fromisoformat(_timestamp(event))
        window = (start.isoformat(), (start + timespan).isoformat())
        for row in run_query(retarget(query, index, window)):
            group = {key: value for key, value in row.items() if key not in {"value_count", "event_count"}}
            groups.add(json.dumps(group, sort_keys=True))
    return groups
