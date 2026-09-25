"""Correlation rules: SQLite-based tests with an explicit sliding time window.

pySigma-backend-sqlite's correlation SQL groups and counts but applies no time window
(checked in test_sqlite_backend_still_ignores_timespan). The harness therefore runs the
backend's SQL for the base rule and applies the rule's timespan itself; see docs/testing.md.
"""

import pytest

from harness import backend_correlation_rows, rule_cases, windowed_correlation_alerts

CORRELATION_RULES = [case for case in rule_cases() if case.is_correlation]


def test_there_is_at_least_one_correlation_rule():
    assert CORRELATION_RULES, "the MVP ships one correlation rule; the harness would silently test nothing"


@pytest.mark.parametrize("case", CORRELATION_RULES, ids=str)
def test_positive_samples_alert(case):
    alerts = windowed_correlation_alerts(case, "positive")
    assert alerts, f"{case.stem}: no correlation alert on tests/data/{case.stem}/positive.ndjson"


@pytest.mark.parametrize("case", CORRELATION_RULES, ids=str)
def test_negative_samples_do_not_alert(case):
    alerts = windowed_correlation_alerts(case, "negative")
    assert not alerts, f"{case.stem}: unexpected correlation alert(s) on negative samples: {alerts}"


@pytest.mark.parametrize("case", CORRELATION_RULES, ids=str)
def test_allowlist_filter_suppresses_allowlisted_samples(case):
    assert not windowed_correlation_alerts(case, "allowlisted"), f"{case.stem}: allowlisted samples alerted"
    assert windowed_correlation_alerts(case, "allowlisted", with_filter=False), (
        f"{case.stem}: allowlisted samples do not alert even without the filter, so the test proves nothing"
    )


@pytest.mark.parametrize("case", CORRELATION_RULES, ids=str)
def test_negative_samples_include_a_window_case(case):
    """The negatives must contain a group that only stays quiet because of the time window.

    Without such a group the negative set cannot tell a correct windowed evaluation
    from one that ignores the timespan.
    """
    assert windowed_correlation_alerts(case, "negative", ignore_timespan=True), (
        f"{case.stem}: add negative events that reach the threshold only when the timespan is ignored"
    )


@pytest.mark.parametrize("case", CORRELATION_RULES, ids=str)
def test_sqlite_backend_still_ignores_timespan(case):
    """Documents the upstream limitation the harness works around.

    If this starts failing, pySigma-backend-sqlite has begun applying the timespan: switch
    the correlation tests to the backend's own SQL and update docs/testing.md.
    """
    windowed = windowed_correlation_alerts(case, "negative")
    naive = backend_correlation_rows(case, "negative")
    assert naive and not windowed
