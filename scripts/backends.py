"""Backend adjustments for the shipped Splunk and ES|QL queries.

pySigma-backend-elasticsearch 2.1.1 (ES|QL) has three problems that break the shipped
queries. All three were found by running the committed queries on Elasticsearch 9.1.5
(tests/test_esql_execution.py):

1. LIKE escaping. A literal backslash is emitted as `\\\\` in the string literal, which
   is a single `\\` in the pattern. ES|QL LIKE treats `\\` as its escape character, so
   `like "*\\\\claude\\\\versions\\\\*"` fails to parse ("escape character is not
   followed by special wildcard char"). Inside LIKE patterns a literal backslash
   must be `\\\\` in the pattern, i.e. `\\\\\\\\` in the string literal.
2. Case sensitivity. Sigma matches strings case-insensitively. ES|QL `==`, `in`,
   `like`, `starts_with` and `ends_with` are case-sensitive. Every string comparison
   is emitted as `to_lower(field) <op> "<lower-cased value>"`.
3. Correlation windows. `date_trunc(1 hours, @timestamp)` buckets are tumbling windows
   that miss bursts straddling an hour boundary. The bucket is dropped: schedule the
   query every 5-10 minutes with a lookback equal to the rule's timespan.

The Splunk backend's `bin _time span=1h` has the same tumbling-window problem and is
replaced with `streamstats time_window=<timespan>`, a sliding window.
The upstream issue text is in docs/upstream-issue-esql-like-escaping.md.
"""

from __future__ import annotations

import re
from typing import ClassVar

from sigma.backends.elasticsearch import ESQLBackend
from sigma.backends.splunk import SplunkBackend
from sigma.conversion.state import ConversionState
from sigma.types import SigmaString

# A double-quoted ES|QL string literal following LIKE.
_LIKE_LITERAL = re.compile(r'(\blike\s+)"((?:[^"\\]|\\.)*)"')


def escape_like_backslashes(expression: str) -> str:
    """Double every escaped backslash inside `like "..."` literals, leave other escapes alone."""

    def fix(match: re.Match) -> str:
        body = re.sub(r"\\(.)", lambda m: r"\\\\" if m.group(1) == "\\" else m.group(0), match.group(2))
        return f'{match.group(1)}"{body}"'

    return _LIKE_LITERAL.sub(fix, expression)


class CaseInsensitiveESQLBackend(ESQLBackend):
    """ES|QL with Sigma's case-insensitive matching, valid LIKE escaping and no time buckets."""

    eq_expression: ClassVar[str] = "to_lower({field}) == {value}"
    startswith_expression: ClassVar[str] = "starts_with(to_lower({field}), {value})"
    endswith_expression: ClassVar[str] = "ends_with(to_lower({field}), {value})"
    wildcard_match_expression: ClassVar[str] = "to_lower({field}) like {value}"
    field_in_list_expression: ClassVar[str] = "to_lower({field}) {op} ({list})"

    event_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "stats": "| stats event_count=count(){fields}{groupby}"
    }
    value_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "stats": "| stats value_count=count_distinct({field}){fields}{groupby}"
    }
    groupby_expression_nofield: ClassVar[dict[str, str]] = {"stats": ""}
    groupby_expression: ClassVar[dict[str, str]] = {"stats": " by {fields}"}
    groupby_field_expression: ClassVar[dict[str, str]] = {"stats": "{field}"}
    groupby_field_expression_joiner: ClassVar[dict[str, str]] = {"stats": ", "}

    def convert_value_str(self, s: SigmaString, state: ConversionState) -> str:
        return super().convert_value_str(s, state).lower()

    def convert_condition_field_eq_val_str(self, cond, state):
        result = super().convert_condition_field_eq_val_str(cond, state)
        return escape_like_backslashes(result) if isinstance(result, str) else result


class SlidingWindowSplunkBackend(SplunkBackend):
    """Splunk with sliding correlation windows (streamstats) instead of fixed bins."""

    event_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "stats": "| sort 0 _time\n| streamstats time_window={timespan} count as event_count by{groupby}",
    }
    value_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "stats": "| sort 0 _time\n| streamstats time_window={timespan} dc({field}) as value_count by{groupby}",
    }
