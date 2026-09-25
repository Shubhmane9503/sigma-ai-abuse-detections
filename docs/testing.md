# How the test harness works

Every rule ships only if the checks below pass. CI (`.github/workflows/ci.yml`) runs them on every pull request and on `main`, and `make test` runs the same checks locally.

```
rules/*.yml + filters/*.yml
   ├─ sigma check (pinned ATT&CK data) ─────────────────────────────────── make check
   ├─ golang_expr ─► json_matcher ─► positive / negative / allowlisted ─┐
   ├─ SQLite (single-event) ─► same samples, must agree with golang_expr ├─ pytest
   ├─ SQLite base rule + sliding window ─► correlation samples ──────────┤
   ├─ Splunk / ES|QL / golang_expr / SQLite ─► tests/snapshots/ ─────────┤
   ├─ tags + atlas: ─► pinned ATT&CK v19.2 / ATLAS 2026.09 ──────────────┤
   └─ tests/data ─► scrub check, conventions (samples, filters, metadata)┘
queries/ ─► regenerated in CI, `git diff --exit-code` (drift check)
```

## Test data layout

```
tests/data/<rule file stem>/
    positive.ndjson     attack events: every event must match
    negative.ndjson     benign look-alikes: no event may match
    allowlisted.ndjson  events the rule matches, which the allowlist filter must suppress
    SOURCE.md           where each file came from and what was changed
```

The spec asked for "at least one match" on positives. The harness is stricter: every positive event must match. A positive file therefore only contains events the rule is meant to catch, and a regression on any one of them is reported with the offending line.

The `allowlisted` set proves each allowlist filter is live: the events must match the rule **without** the filter and must not match **with** it. A filter that points at the wrong rule, the wrong log source or a misspelled field fails this test.

`tests/test_meta.py` fails if any rule lacks one of the three sample files, a `SOURCE.md`, an allowlist filter that references it, or required metadata.

## Single-event rules: golang_expr + json_matcher

Mirrors SigmaHQ's [regression data](https://github.com/SigmaHQ/sigma/blob/master/regression_data/README.md) approach: the rule is converted (with its filter, exactly as `sigma convert --filter` would) by `pySigma-backend-golangexpr`, and the expression is evaluated over the NDJSON by SigmaHQ's [json_matcher](https://github.com/SigmaHQ/json_matcher) v0.0.2 (built from pinned commit `3bb3022` by `make setup`).

Workarounds, each covered by a test in `tests/test_harness.py` that fails once it is no longer needed:

| Problem | Workaround |
|---|---|
| json_matcher splits input on `\n` and fails on the empty string after a trailing newline (which almost every tool writes). | `normalize_ndjson()` strips trailing and blank lines and converts CRLF before replay. `test_json_matcher_still_fails_on_trailing_newline` tracks the upstream bug. The committed samples keep their trailing newline, so the workaround runs on every test. |
| The golang_expr backend emits field names bare, so a Sigma proxy field such as `cs-host` becomes the expression `cs - host`. | `ReplayBackend` emits such names as `$env["cs-host"]`. Dotted names keep the backend's nested `a?.b` form. |
| `go install` of json_matcher fails because its `go.mod` declares the module path `sigma_regression`. | The Makefile clones the pinned commit and runs `go build`. |
| The backend's case-sensitive templates (`\|cased`) emit invalid expressions. | No rule uses `\|cased`. Sigma matching is case-insensitive by default. |

### Second engine: SQLite with SQL NULL semantics

golang_expr treats a missing field as an empty string. SQL-style SIEM backends such as ES|QL treat it as NULL, and `NOT field = 'x'` on a NULL is unknown, so the event is dropped. An allowlist filter on a field that some events lack therefore silently hides those events in production while every golang_expr test still passes.

`test_sqlite_engine_agrees_with_golang_expr` converts each single-event rule with `pySigma-backend-sqlite`, loads the samples into SQLite (nested objects flattened to dotted column names, `COLLATE NOCASE` to match Sigma's case-insensitivity) and requires the same per-event result as golang_expr. The samples include events without optional fields (an IAM user with no `sessionContext`, a proxy event with no `cs-username`) so this check has something to catch. It found exactly this bug in the first drafts of the Bedrock and proxy allowlists (see [tuning.md](tuning.md#allowlist-fields-must-always-be-present)).

## Correlation rules: SQLite with an explicit window

The MVP's correlation rule (`aws_bedrock_invoke_model_multi_region`) is a `value_count` of `awsRegion` per `userIdentity.arn` over `1h`, threshold 3.

**Known issue:** `pySigma-backend-sqlite` 1.2.4 ignores the timespan. The generated SQL is:

```sql
SELECT `userIdentity.arn`, COUNT(DISTINCT awsRegion) AS value_count
FROM (SELECT * FROM logs WHERE eventSource='bedrock.amazonaws.com' AND (eventName='InvokeModel' OR ...)
      AND (NOT `userIdentity.arn` LIKE 'arn:aws:sts::111122223333:assumed-role/allowlisted-multi-region-inference/%' ESCAPE '\'))
AS subquery GROUP BY `userIdentity.arn` HAVING value_count >= 3
```

It has no time predicate, so it alerts on three regions spread over any period.

**Chosen workaround:** `windowed_correlation_alerts()` in `tests/harness.py`

1. converts the base rule (with its allowlist filter) with the SQLite backend and runs that SQL, so event selection and filtering still come from the backend;
2. reads `group-by`, `timespan`, the condition field and the threshold from the parsed correlation rule;
3. slides a window of `timespan` over each group's events (sorted by the log source's timestamp field, `eventTime` for CloudTrail) and alerts if any window reaches the threshold. `value_count` and `event_count` are supported, and other correlation types fail loudly.

Supporting tests:

- `test_negative_samples_include_a_window_case` requires the negatives to contain a group that alerts only if the timespan is ignored (`batch-eval`: three regions within 61 minutes). A mutation check confirmed that widening the rule's timespan to even 65 minutes makes the negative test fail.
- `test_sqlite_backend_still_ignores_timespan` asserts that the backend's own SQL still alerts on that negative. When the upstream bug is fixed this test fails, and the correlation tests can switch to the backend's SQL.

**Backend note:** the Splunk (`bin _time span=1h`) and ES|QL (`date_trunc(1hours, @timestamp)`) conversions use fixed hourly buckets, not a sliding window. Activity that straddles a bucket boundary (for example 10:50, 11:05, 11:20) is missed by those queries, although the sliding-window test flags it. This is documented in the rule description.

## Conversion snapshots and committed queries

`scripts/conversions.py` converts every rule with its filter to Splunk SPL (`pipelines/splunk/`), ES|QL (`pipelines/esql/`), golang_expr and SQLite.

- `tests/snapshots/<rule>.json` holds all four outputs. `test_snapshots.py` compares a fresh conversion against them, so a backend upgrade, pipeline edit or rule change that alters any query shows up as a failing test and a reviewable diff.
- `queries/splunk/*.spl` and `queries/esql/*.esql` are the user-facing queries. CI runs `make convert` and `git diff --exit-code queries/`, and pytest also compares them, so committed queries cannot drift from the rules.
- After an intentional change: `make snapshots`, then review the diff in the pull request.
- The ES|QL pipelines use `strict_field_mapping_failure`: a rule that uses a CloudTrail, proxy or endpoint field with no ECS mapping fails to convert instead of producing a query against a field that does not exist.

## Mapping validation

- `mappings/attack-v19.2/enterprise-attack-19.2.min.json` and `mappings/atlas-2026.09/atlas-2026.09.min.json` are small extracts of the pinned upstream releases. `scripts/fetch_framework_data.py` downloads the upstream files from pinned commits, verifies their SHA-256 and regenerates the extracts. The CI job `framework-data` runs it with `--check`.
- `make mappings` (`scripts/validate_mappings.py`, also run by `tests/test_mappings.py`) checks every ATT&CK tag against v19.2 (unknown, revoked or deprecated IDs fail), every technique against the rule's tactic tags, and every `atlas:` ID against ATLAS 2026.09. ATLAS has no deprecation flag in its v6 data format: removed IDs are simply absent, so presence is the check.
- `make check` runs `sigma check` through `scripts/sigma_check.py`, which points pySigma's ATT&CK tag validator at the same pinned extract. By default pySigma downloads the newest ATT&CK release, which would make results change whenever MITRE publishes. The D3FEND tag validator is excluded because it also downloads data, and no rule uses D3FEND tags.

## Sample hygiene

`tests/test_scrub.py` (and `make scrub`) fails on AWS account IDs other than documentation placeholders, non-example access keys, public IP addresses, non-placeholder Azure subscription and tenant IDs, emails outside reserved domains, private keys and common API token formats. `scripts/scrub_samples.py --apply FILE` performs the mechanical replacements consistently. User and host names still need a manual review. CI also runs gitleaks over the full git history.

## Demo: the suite catches a broken rule

`make demo` copies the repository to a temporary directory, renames the `eventSource` field in the Bedrock model-access rule to `eventSrc` (a plausible typo) and runs the replay tests there:

```
FAILED tests/test_replay.py::test_positive_samples_match[aws_bedrock_model_access_enabled]
FAILED tests/test_replay.py::test_allowlisted_samples_match_without_filter[aws_bedrock_model_access_enabled]
2 failed, 5 passed, 42 deselected

As expected, the tests failed: a pull request with this change would be blocked.
```

The failure lists every positive event that no longer matches. Other mutations checked while building the harness: removing the `ActivityStatusValue: Success` condition from the Azure rule (negative test fails), a null-unsafe `cs-username` allowlist (engine agreement test fails), widening the correlation timespan (negative test fails), and pointing a filter at the wrong rule (meta, replay and snapshot tests fail).

## Adding a rule

1. Write `tests/data/<stem>/positive.ndjson`, `negative.ndjson`, `allowlisted.ndjson` and `SOURCE.md` first, then check that a deliberately wrong rule fails.
2. Add `rules/<area>/<stem>.yml` with ATT&CK tags and an `atlas:` list, and `filters/<stem>_allowlist.yml`.
3. For a new log source, add pipeline entries in `pipelines/splunk/` and `pipelines/esql/`. For a correlation rule, add its timestamp field to `TIMESTAMP_FIELDS` in `tests/harness.py`.
4. Run `make snapshots matrix test` and review the generated diff.
