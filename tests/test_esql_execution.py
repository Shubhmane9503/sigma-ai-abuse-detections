"""Execute the committed ES|QL queries on a real Elasticsearch.

Runs only when ESQL_TEST_URL points at an Elasticsearch 9.x node (the CI job
"ES|QL execution" starts one as a service container). Locally:

    docker run -d -p 9200:9200 -e discovery.type=single-node \\
        -e xpack.security.enabled=false elasticsearch:9.1.5
    ESQL_TEST_URL=http://localhost:9200 make test-esql

For every rule the samples are loaded into Elasticsearch (translated to ECS with the
pipelines' own field mappings) and the committed query from queries/esql/ runs against them:
  positive     every event matches (correlation: every group in the file alerts)
  negative     nothing matches
  allowlisted  nothing matches
Documented gaps listed in tests/esql_known_gaps.yml are xfail(strict=True).
"""

from datetime import timedelta

import pytest

from esql_harness import correlation_alert_groups, es_url, known_gaps, matched_lines
from harness import SAMPLE_KINDS, flatten, load_events, rule_cases

pytestmark = pytest.mark.skipif(not es_url(), reason="ESQL_TEST_URL not set (see module docstring)")

GAPS = known_gaps()


def _params():
    for case in rule_cases():
        for kind in SAMPLE_KINDS:
            reason = GAPS.get(case.stem, {}).get(kind)
            marks = [pytest.mark.xfail(strict=True, reason=f"known ES|QL gap: {reason}")] if reason else []
            yield pytest.param(case, kind, marks=marks, id=f"{case.stem}-{kind}")


def _correlation_spec(case):
    from sigma.correlations import SigmaCorrelationRule

    correlation = next(r for r in case.collection(with_filter=False) if isinstance(r, SigmaCorrelationRule))
    return timedelta(seconds=correlation.timespan.seconds), list(correlation.group_by)


@pytest.mark.parametrize("case,kind", list(_params()))
def test_committed_esql_query(case, kind):
    if case.is_correlation:
        timespan, group_by = _correlation_spec(case)
        alerts = correlation_alert_groups(case, kind, timespan)
        if kind == "positive":
            expected = {tuple(flatten(e).get(f) for f in group_by) for e in load_events(case.sample(kind))}
            assert len(alerts) == len(expected), (
                f"{case.stem}: expected an alert for each of the {len(expected)} groups in the positive samples "
                f"{sorted(expected)}, got {sorted(alerts)}"
            )
        else:
            assert not alerts, f"{case.stem}/{kind}: unexpected alerts {sorted(alerts)}"
        return

    results = matched_lines(case, kind)
    events = load_events(case.sample(kind))
    want = kind == "positive"
    wrong = [f"  line {i + 1}: {events[i]}" for i, matched in enumerate(results) if matched != want]
    verb = "missed" if want else "matched unexpectedly"
    assert not wrong, f"{case.stem}/{kind}: ES|QL {verb} {len(wrong)} event(s):\n" + "\n".join(wrong)
