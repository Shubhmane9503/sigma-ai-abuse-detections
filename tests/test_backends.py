"""Unit tests for the Splunk and ES|QL backend adjustments in scripts/backends.py."""

import pytest
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

from backends import CaseInsensitiveESQLBackend, SlidingWindowSplunkBackend, escape_like_backslashes


def rule(detection: str) -> SigmaCollection:
    return SigmaCollection.from_yaml(
        f"""
title: t
id: 0b0d5a52-7d3c-4b6e-9f0e-1c2d3e4f5a6b
status: test
logsource:
    category: process_creation
detection:
{detection}
    condition: selection
level: low
"""
    )


def esql(detection: str) -> str:
    return CaseInsensitiveESQLBackend(processing_pipeline=ProcessingPipeline()).convert(rule(detection))[0]


@pytest.mark.parametrize(
    "before,after",
    [
        (r'x like "*\\claude\\versions\\*"', r'x like "*\\\\claude\\\\versions\\\\*"'),
        (r'x like "*a\"b*"', r'x like "*a\"b*"'),  # escaped quote untouched
        (r'ends_with(x, "\\claude.exe")', r'ends_with(x, "\\claude.exe")'),  # not a LIKE: untouched
        (r'x like "*\\a*" or y == "\\b"', r'x like "*\\\\a*" or y == "\\b"'),
    ],
)
def test_escape_like_backslashes(before, after):
    assert escape_like_backslashes(before) == after


def test_like_pattern_with_backslash_is_valid_esql():
    query = esql("    selection:\n        Image|contains: '\\claude\\versions\\'")
    assert r'like "*\\\\claude\\\\versions\\\\*"' in query


def test_backslash_outside_like_is_single_escaped():
    query = esql("    selection:\n        Image|endswith: '\\claude.exe'")
    assert r'ends_with(to_lower(Image), "\\claude.exe")' in query


@pytest.mark.parametrize(
    "detection,expected",
    [
        ("    selection:\n        A: MiXeD", 'to_lower(A) == "mixed"'),
        ("    selection:\n        A:\n            - One\n            - TWO", 'to_lower(A) in ("one", "two")'),
        ("    selection:\n        A|contains: SPCANARY-", 'to_lower(A) like "*spcanary-*"'),
        ("    selection:\n        A|startswith: Arn:AWS", 'starts_with(to_lower(A), "arn:aws")'),
        ("    selection:\n        A|endswith: /Cursor", 'ends_with(to_lower(A), "/cursor")'),
    ],
)
def test_esql_string_matching_is_case_insensitive(detection, expected):
    assert expected in esql(detection)


CORRELATION = """
title: base
id: 6f5a3c1e-2b4d-4e8f-9a1b-2c3d4e5f6a7b
name: base_rule
status: test
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: InvokeModel
    condition: selection
level: low
---
title: corr
id: 7a6b4d2f-3c5e-4f9a-8b2c-3d4e5f6a7b8c
status: test
correlation:
    type: value_count
    rules:
        - base_rule
    group-by:
        - userIdentity.arn
    timespan: 1h
    condition:
        gte: 3
        field: awsRegion
level: high
"""


def test_esql_correlation_has_no_time_bucket():
    query = CaseInsensitiveESQLBackend(processing_pipeline=ProcessingPipeline()).convert(
        SigmaCollection.from_yaml(CORRELATION)
    )[0]
    assert "date_trunc" not in query and "timebucket" not in query
    assert "| stats value_count=count_distinct(awsRegion) by userIdentity.arn" in query


def test_splunk_correlation_uses_sliding_window():
    query = SlidingWindowSplunkBackend(processing_pipeline=ProcessingPipeline()).convert(
        SigmaCollection.from_yaml(CORRELATION)
    )[0]
    assert "bin _time" not in query
    assert "| streamstats time_window=1h dc(awsRegion) as value_count by userIdentity.arn" in query
