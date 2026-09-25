"""Single-event rules: replay positive, negative and allowlisted samples.

Each rule is converted (with its allowlist filter) to golang_expr and evaluated by
json_matcher over its NDJSON samples:
  positive.ndjson     every event must match
  negative.ndjson     no event may match
  allowlisted.ndjson  no event may match with the filter, every event must match without it
                      (proves the allowlist hook is live, not just syntactically valid)
The same samples are also evaluated with the SQLite backend, whose SQL NULL semantics
match SQL-style SIEM backends such as ES|QL, and both engines must agree.
"""

import pytest

from harness import load_events, replay, rule_cases, sqlite_replay

SINGLE_EVENT_RULES = [case for case in rule_cases() if not case.is_correlation]


def _describe(case, kind, results, want):
    events = load_events(case.sample(kind))
    bad = [f"  line {i + 1}: {events[i]}" for i, matched in enumerate(results) if matched != want]
    verb = "did not match" if want else "matched unexpectedly"
    return f"{case.stem}: {len(bad)} event(s) in tests/data/{case.stem}/{kind}.ndjson {verb}:\n" + "\n".join(bad)


@pytest.mark.parametrize("case", SINGLE_EVENT_RULES, ids=str)
def test_positive_samples_match(case):
    results = replay(case, "positive")
    assert results, f"{case.stem}: positive sample file is empty"
    assert all(results), _describe(case, "positive", results, True)


@pytest.mark.parametrize("case", SINGLE_EVENT_RULES, ids=str)
def test_negative_samples_do_not_match(case):
    results = replay(case, "negative")
    assert results, f"{case.stem}: negative sample file is empty"
    assert not any(results), _describe(case, "negative", results, False)


@pytest.mark.parametrize("case", SINGLE_EVENT_RULES, ids=str)
def test_allowlist_filter_suppresses_allowlisted_samples(case):
    results = replay(case, "allowlisted")
    assert results, f"{case.stem}: allowlisted sample file is empty"
    assert not any(results), _describe(case, "allowlisted", results, False)


@pytest.mark.parametrize("case", SINGLE_EVENT_RULES, ids=str)
def test_allowlisted_samples_match_without_filter(case):
    results = replay(case, "allowlisted", with_filter=False)
    assert all(results), (
        "the allowlist filter is not what suppresses these events, so the test proves nothing:\n"
        + _describe(case, "allowlisted", results, True)
    )


@pytest.mark.parametrize("kind", ["positive", "negative", "allowlisted"])
@pytest.mark.parametrize("case", SINGLE_EVENT_RULES, ids=str)
def test_sqlite_engine_agrees_with_golang_expr(case, kind):
    expected = replay(case, kind)
    actual = sqlite_replay(case, kind)
    events = load_events(case.sample(kind))
    differ = [
        f"  line {i + 1}: golang_expr={g} sqlite={s}: {events[i]}"
        for i, (g, s) in enumerate(zip(expected, actual))
        if g != s
    ]
    assert actual == expected, (
        f"{case.stem}/{kind}: SQLite (SQL NULL semantics) and golang_expr disagree. "
        "A NOT filter on a field some events lack is the usual cause (see docs/tuning.md).\n" + "\n".join(differ)
    )
