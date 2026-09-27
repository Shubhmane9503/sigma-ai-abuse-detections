"""Rule conversion shared by `make convert`, `make snapshots` and the snapshot tests.

Each rule is converted together with its allowlist filter, the same way
`sigma convert --filter filters/<rule>_allowlist.yml` would:

  splunk       Splunk SPL with the pipelines in pipelines/splunk/ (sliding correlation windows)
  esql         Elastic ES|QL with the pipelines in pipelines/esql/ (case-insensitive, valid
               LIKE escaping, no correlation time buckets; see scripts/backends.py)
  golang_expr  expression replayed by the tests (single-event rules only)
  sqlite       SQL used by the correlation tests
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sigma.processing.pipeline import ProcessingPipeline

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from backends import CaseInsensitiveESQLBackend, SlidingWindowSplunkBackend  # noqa: E402
from harness import PIPELINES_DIR, SNAPSHOT_DIR, ReplayBackend, RuleCase, SqlReplayBackend, rule_cases  # noqa: E402

QUERY_DIRS = {"splunk": ROOT / "queries" / "splunk", "esql": ROOT / "queries" / "esql"}

# Notes written as comments at the top of the committed query files (not into snapshots).
# ES|QL takes // line comments; Splunk takes ```...``` comments (Splunk 8.1+).
QUERY_NOTES = {
    "llm_gateway_system_prompt_canary_in_output": [
        "The canary token SPCANARY-7f3c9a1e5b2d below is a test placeholder from",
        "filters/llm_gateway_system_prompt_canary_in_output_tokens.yml. Put your own tokens in that",
        "(private) filter and regenerate this query (make convert) before using it.",
    ],
    "aws_bedrock_invoke_model_multi_region": [
        "Scheduled-detection only: run every 5-10 minutes with a 60-minute lookback.",
        "Not for ad-hoc searches over ranges longer than 1 hour: the query has no time window of",
        "its own and would count regions across the whole range.",
    ],
}
QUERY_SUFFIX = {"splunk": ".spl", "esql": ".esql"}


def load_pipeline(target: str) -> ProcessingPipeline:
    pipeline = ProcessingPipeline()
    for path in sorted((PIPELINES_DIR / target).glob("*.yml")):
        pipeline += ProcessingPipeline.from_yaml(path.read_text(encoding="utf-8"))
    return pipeline


def make_backends() -> dict:
    return {
        "splunk": SlidingWindowSplunkBackend(processing_pipeline=load_pipeline("splunk")),
        "esql": CaseInsensitiveESQLBackend(processing_pipeline=load_pipeline("esql")),
        "golang_expr": ReplayBackend(),
        "sqlite": SqlReplayBackend(),
    }


def convert(case: RuleCase) -> dict[str, list[str]]:
    """Convert one rule (with its filter) to every target. Unsupported targets are omitted."""
    results = {}
    for name, backend in make_backends().items():
        if name == "golang_expr" and case.is_correlation:
            continue  # golang_expr has no correlation support; the SQLite harness covers these rules
        results[name] = [str(query) for query in backend.convert(case.collection(with_filter=True))]
    return results


def render_query_file(queries: list[str], target: str = "", notes: list[str] | None = None) -> str:
    body = "\n\n".join(query.strip() for query in queries) + "\n"
    if not notes:
        return body
    if target == "esql":
        header = "".join(f"// {line}\n" for line in notes)
    else:
        header = "".join(f"```{line}```\n" for line in notes)
    return header + body


def render_snapshot(case: RuleCase, results: dict[str, list[str]]) -> str:
    snapshot = {"rule": str(case.path.relative_to(ROOT)), "filters": [str(p.relative_to(ROOT)) for p in case.filter_paths], **results}
    return json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n"


def expected_files() -> dict[Path, str]:
    """Every generated file (committed queries and snapshots) with its expected content."""
    files = {}
    for case in rule_cases():
        results = convert(case)
        for target, directory in QUERY_DIRS.items():
            files[directory / f"{case.stem}{QUERY_SUFFIX[target]}"] = render_query_file(
                results[target], target, QUERY_NOTES.get(case.stem)
            )
        files[SNAPSHOT_DIR / f"{case.stem}.json"] = render_snapshot(case, results)
    return files


def main(argv: list[str]) -> int:
    """Write generated files. With --queries-only, only queries/ is written."""
    queries_only = "--queries-only" in argv
    for path, content in expected_files().items():
        if queries_only and SNAPSHOT_DIR in path.parents:
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            path.write_text(content, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
