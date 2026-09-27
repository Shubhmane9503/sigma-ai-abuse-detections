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
   is emitted as `to_lower(field) <op> "<lower-cased value>"`, except on fields that
   ECS types as `ip` (source.ip, destination.ip, ... any *.ip): to_lower() on an ip field
   is a verification error that rejects the whole query, so those compare with
   `field == to_ip("<value>")` / `field in (to_ip(...), ...)`. Use Sigma's |cidr for
   ranges (emitted as cidr_match()).
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
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.types import SigmaString

# ECS fields of type `ip` (ECS v9.5.0). Any other field ending in ".ip" is treated the same way.
ECS_IP_FIELDS = frozenset({"source.ip", "destination.ip", "client.ip", "server.ip", "host.ip"})


def is_ip_field(field: str) -> bool:
    return field in ECS_IP_FIELDS or field.endswith(".ip")

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

    def _ip_literal(self, cond, state: ConversionState) -> str:
        value = cond.value
        if value.contains_special():
            raise SigmaFeatureNotSupportedByBackendError(
                f"wildcards on ip-typed field {cond.field} are not supported in ES|QL; use the |cidr modifier"
            )
        # Plain (not lower-cased) string literal: IPv6 hex digits are case-insensitive for to_ip anyway.
        return f"to_ip({ESQLBackend.convert_value_str(self, value, state)})"

    def convert_condition_field_eq_val_str(self, cond, state):
        if is_ip_field(cond.field):
            return f"{self.escape_and_quote_field(cond.field)} == {self._ip_literal(cond, state)}"
        result = super().convert_condition_field_eq_val_str(cond, state)
        return escape_like_backslashes(result) if isinstance(result, str) else result

    def convert_condition_as_in_expression(self, cond, state):
        field = cond.args[0].field
        if is_ip_field(field) and all(arg.field == field for arg in cond.args):
            values = ", ".join(self._ip_literal(arg, state) for arg in cond.args)
            op = self.or_in_operator if type(cond).__name__ == "ConditionOR" else self.and_in_operator
            return f"{self.escape_and_quote_field(field)} {op} ({values})"
        return super().convert_condition_as_in_expression(cond, state)


class SlidingWindowSplunkBackend(SplunkBackend):
    """Splunk with sliding correlation windows (streamstats) instead of fixed bins."""

    event_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "stats": "| sort 0 _time\n| streamstats time_window={timespan} count as event_count by{groupby}",
    }
    value_count_aggregation_expression: ClassVar[dict[str, str]] = {
        "stats": "| sort 0 _time\n| streamstats time_window={timespan} dc({field}) as value_count by{groupby}",
    }
