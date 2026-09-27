# How the test harness works

CI (`.github/workflows/ci.yml`) runs the checks below on every pull request and on `main`, and `make test` runs the same checks locally (except the ES|QL execution job, `make test-esql`). Branch protection on `main` requires "Rules and tests", "Secret scan" and "Pinned ATT&CK / ATLAS extracts match upstream" to pass (branch up to date, admins included). "ES|QL execution" runs on every pull request but is not a required check.

What each layer proves:

- **Rule logic** is proven by replaying the samples through two engines (golang_expr/json_matcher and SQLite).
- **Committed ES|QL queries** are executed on Elasticsearch 9.1.5 against the same samples (CI job "ES|QL execution").
- **Committed Splunk queries** are generated and snapshot-tested only. They are not executed on Splunk.

```
rules/*.yml + filters/*.yml
   ├─ sigma check (pinned ATT&CK data) ─────────────────────────────────── make check
   ├─ golang_expr ─► json_matcher ─► positive / negative / allowlisted ─┐
   ├─ SQLite (single-event) ─► same samples, must agree with golang_expr ├─ pytest
   ├─ SQLite base rule + sliding window ─► correlation samples ──────────┤
   ├─ Splunk / ES|QL / golang_expr / SQLite ─► tests/snapshots/ ─────────┤
   ├─ queries/esql/*.esql ─► Elasticsearch 9.1.5 with ECS-translated samples ┤ (CI job)
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
| The backend's `\|exists` template (`field in $env`) is wrong for nested fields. | `ReplayBackend` emits `field != nil`. `?.` access is nil-safe. |

### Second engine: SQLite with SQL NULL semantics

golang_expr treats a missing field as an empty string. SQL-style SIEM backends such as ES|QL treat it as NULL, and `NOT field = 'x'` on a NULL is unknown, so the event is dropped. An allowlist filter on a field that some events lack therefore silently hides those events in production while every golang_expr test still passes.

`test_sqlite_engine_agrees_with_golang_expr` converts each single-event rule with `pySigma-backend-sqlite`, loads the samples into SQLite (nested objects flattened to dotted column names, `COLLATE NOCASE` to match Sigma's case-insensitivity) and requires the same per-event result as golang_expr. The samples include events without optional fields (an IAM user with no `sessionContext`, a proxy event with no `cs-username`) so this check has something to catch. It found exactly this bug in the first drafts of the Bedrock and proxy allowlists (see [tuning.md](tuning.md#allowlist-fields-must-always-be-present)). The SQLite backend's `|exists` template (`field = field`) is NULL, not false, for a missing field. The harness's `SqlReplayBackend` emits `IS NOT NULL` instead, which is what ES|QL does (`is not null`). Removing the `|exists` guard from the canary token filter makes both this test and the ES|QL execution test fail.

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
- `test_positive_samples_alert` requires every group in the positive file to alert, including `ci-deployer`, whose burst (03:50, 03:52, 04:10) straddles an hour boundary.

**Shipped correlation queries:** the upstream Splunk (`bin _time span=1h`) and ES|QL (`date_trunc(1 hour, @timestamp)`) conversions use fixed hourly buckets and miss that straddling burst. This was verified on Elasticsearch. `scripts/backends.py` replaces them: Splunk uses `streamstats time_window=1h` (a sliding window), and ES|QL drops the bucket and is meant to be scheduled every 5-10 minutes with a 60-minute lookback. The ES|QL execution test emulates that schedule by running the query once per window `[t, t + 1h)` for every event time `t`.

## Conversion snapshots and committed queries

`scripts/conversions.py` converts every rule with its filters to Splunk SPL (`pipelines/splunk/`), ES|QL (`pipelines/esql/`), golang_expr and SQLite. The Splunk and ES|QL backends are subclassed in `scripts/backends.py` (unit tests: `tests/test_backends.py`):

- **ES|QL `LIKE` escaping.** pySigma-backend-elasticsearch 2.1.1 emits `like "*\\claude\\versions\\*"`, which Elasticsearch rejects ("escape character is not followed by special wildcard char"). This broke 3 of the 8 shipped queries. Backslashes are doubled inside `LIKE` patterns only. The draft upstream report is in [upstream-issue-esql-like-escaping.md](upstream-issue-esql-like-escaping.md).
- **ES|QL case sensitivity.** Every string comparison becomes `to_lower(field) <op> "<lower-cased value>"`, restoring Sigma's case-insensitive matching. The exception is ECS `ip` fields (`source.ip`, `destination.ip`, any `*.ip`), where `to_lower()` is a verification error that rejects the whole query. They compare with `field == to_ip("…")` or `field in (to_ip(…), …)`, and `|cidr` becomes `cidr_match()`. Wildcards on an ip field fail conversion. `test_no_committed_esql_query_lowercases_an_ip_field` scans every committed ES|QL query for this mistake.
- **Correlation windows**, as described above.

- `tests/snapshots/<rule>.json` holds all four outputs. `test_snapshots.py` compares a fresh conversion against them, so a backend upgrade, pipeline edit or rule change that alters any query shows up as a failing test and a reviewable diff.
- `queries/splunk/*.spl` and `queries/esql/*.esql` are the user-facing queries. CI runs `make convert` and `git diff --exit-code queries/`, and pytest also compares them, so committed queries cannot drift from the rules.
- After an intentional change: `make snapshots`, then review the diff in the pull request.
- The ES|QL pipelines use `strict_field_mapping_failure`: a rule that uses a CloudTrail, proxy or endpoint field with no ECS mapping fails to convert instead of producing a query against a field that does not exist.

## ES|QL execution on Elasticsearch

`tests/test_esql_execution.py` runs when `ESQL_TEST_URL` points at an Elasticsearch 9.x node (the CI job "ES|QL execution" uses an `elasticsearch:9.1.5` service container; locally see `make test-esql`). For every rule and sample kind it:

1. translates the samples to the shape the ES|QL pipelines expect, using the `field_name_mapping` and `add_condition` entries of `pipelines/esql/*.yml` themselves (for example `event.type: start` for process events). `@timestamp` comes from `eventTime`, `TimeGenerated`, `UtcTime` or `timestamp`. Every field the pipelines emit is mapped with its real ECS type (`ECS_FIELD_TYPES` in `tests/esql_harness.py`, taken from ECS v9.5.0): `ip` for `source.ip` and `destination.ip`, `wildcard` for `process.command_line`, `process.parent.command_line`, `url.original` and `url.path`, `long` for `http.response.status_code`, and `keyword` for the rest. Other strings default to `keyword`. `test_every_pipeline_field_has_an_ecs_type` fails if a pipeline starts emitting an untyped field. Log sources without an ES|QL pipeline keep their raw field names, which is what their queries use. Typing matters: until 27 Sep 2026 every string was indexed as keyword, so the proxy query's `to_lower(source.ip)` passed here but was rejected on real ECS data;
2. indexes them into a per-rule, per-kind index;
3. runs the committed `queries/esql/<rule>.esql` with its `from` clause pointed at that index;
4. asserts that every positive matches and no negative or allowlisted event does. Correlation queries must alert on every positive group.

Documented gaps go in `tests/esql_known_gaps.yml` and become `xfail(strict=True)`: if a gap disappears, the test fails until the file is updated. It is currently empty. The coverage matrix shows ES|QL as "tested" or "known gap" from the same file. Run against the queries on `main` before this change, the test failed 12 of 24 cases: the three `LIKE` parse errors, the upper-case Azure and lower-case canary positives, and the straddling correlation burst.

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

As expected, the tests failed: a pull request with this change would fail the required "Rules and tests" check and could not be merged.
```

The failure lists every positive event that no longer matches. Other mutations checked while building the harness: removing the `ActivityStatusValue: Success` condition from the Azure rule (negative test fails), a null-unsafe `cs-username` allowlist (engine agreement test fails), widening the correlation timespan (negative test fails), and pointing a filter at the wrong rule (meta, replay and snapshot tests fail).

## Adding a rule

1. Write `tests/data/<stem>/positive.ndjson`, `negative.ndjson`, `allowlisted.ndjson` and `SOURCE.md` first, then check that a deliberately wrong rule fails.
2. Add `rules/<area>/<stem>.yml` with ATT&CK tags and an `atlas:` list, and `filters/<stem>_allowlist.yml`. Extra filters named `filters/<stem>_<name>.yml` are applied too (for example the canary token list).
3. For a new log source, add pipeline entries in `pipelines/splunk/` and `pipelines/esql/`. For a correlation rule, add its timestamp field to `TIMESTAMP_FIELDS` in `tests/harness.py`.
4. Run `make snapshots matrix test` (and `make test-esql` against a local Elasticsearch) and review the generated diff.
