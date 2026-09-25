"""Unit tests for the harness itself, including the json_matcher workarounds."""

import subprocess
import tempfile

import pytest
from sigma.collection import SigmaCollection

from harness import flatten, json_matcher_path, normalize_ndjson, run_json_matcher, to_golang_expr

EVENTS = b'{"a": "x"}\n{"a": "y"}\n'


def test_normalize_strips_trailing_newline():
    assert normalize_ndjson(EVENTS) == b'{"a": "x"}\n{"a": "y"}'


def test_normalize_handles_crlf_and_blank_lines():
    assert normalize_ndjson(b'{"a": 1}\r\n\r\n{"a": 2}\r\n') == b'{"a": 1}\n{"a": 2}'


def test_json_matcher_still_fails_on_trailing_newline():
    """Documents why normalize_ndjson exists (json_matcher v0.0.2).

    If this starts failing, json_matcher accepts trailing newlines and the normalisation
    step can be dropped (update docs/testing.md).
    """
    with tempfile.NamedTemporaryFile("wb", suffix=".ndjson") as handle:
        handle.write(EVENTS)
        handle.flush()
        result = subprocess.run(
            [json_matcher_path(), "--test-type", "ndjson", "--event", handle.name, "--expr", 'a == "x"'],
            capture_output=True,
            text=True,
            check=False,
        )
    assert result.returncode != 0


def test_run_json_matcher_with_trailing_newline():
    assert run_json_matcher('a == "x"', EVENTS) == [True, False]


def rule(detection: str) -> SigmaCollection:
    return SigmaCollection.from_yaml(
        f"""
title: t
id: 5d5c7bd5-2d4e-4d8f-9d5a-3c3f0e3d0f11
status: test
logsource:
    category: proxy
detection:
{detection}
    condition: selection
level: low
"""
    )


def test_hyphenated_fields_are_addressable():
    expression = to_golang_expr(rule("    selection:\n        cs-host: api.openai.com"))
    assert '$env["cs-host"]' in expression
    assert run_json_matcher(expression, b'{"cs-host": "API.openai.com"}\n{"cs-host": "example.com"}') == [True, False]


def test_dotted_fields_are_nested():
    expression = to_golang_expr(rule("    selection:\n        a.b|contains: needle"))
    assert run_json_matcher(expression, b'{"a": {"b": "hayneedlestack"}}\n{"a": {}}\n{}') == [True, False, False]


def test_flatten():
    assert flatten({"a": {"b": 1, "c": {"d": 2}}, "e": 3}) == {"a.b": 1, "a.c.d": 2, "e": 3}


@pytest.mark.parametrize("value", ["x", "X"])
def test_matching_is_case_insensitive(value):
    expression = to_golang_expr(rule("    selection:\n        a: x"))
    assert run_json_matcher(expression, f'{{"a": "{value}"}}'.encode()) == [True]
