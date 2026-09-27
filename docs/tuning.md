# Tuning: false positives and allowlists

Every rule has an allowlist hook in `filters/`: a [Sigma filter](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-filters-specification.md) that targets the rule by ID. You tune a rule by editing its filter, never the rule itself, so rule updates from this repository merge cleanly.

```bash
# convert one rule with your tuned filter
sigma convert -t splunk -p pipelines/splunk/cloudtrail.yml \
    --filter filters/aws_bedrock_model_access_enabled_allowlist.yml \
    rules/cloud/aws/aws_bedrock_model_access_enabled.yml
```

Every filter ships with an obviously fake placeholder value (documentation account ID `111122223333`, RFC 5737 addresses, `allowlisted-*` names). The tests use those placeholders to prove the hook works (`tests/data/<rule>/allowlisted.ndjson`). If you replace them in a fork, update the `allowlisted` samples too, or run `make snapshots test` and accept the query diff.

## Per-rule guidance

| Rule | Filter keys on | Typical entries | Notes |
|---|---|---|---|
| Bedrock model access use case / agreement | `userIdentity.arn` prefix | `arn:aws:sts::<acct>:assumed-role/<platform-admin-role>/`, IaC deployer role | Since AWS's Oct 2025 simplified model access these calls are rarer still, but an attacker may not need them at all. Treat this as a precursor signal. |
| Bedrock multi-region invocation | `userIdentity.arn` prefix (applied to the base rule) | Multi-region failover services, model evaluation jobs | Sigma filters cannot target correlation rules, so this filter removes the identity's events before counting. |
| Azure AI keys listed/regenerated | `Caller` | Key-rotation automation, deployment pipelines, app managed identities (object IDs) | The Azure portal calls `listKeys` when someone opens *Keys and Endpoint*, so administrators viewing keys will alert. |
| Unapproved LLM API use | `src_ip` | AI gateway, sanctioned application servers, developer VDI ranges | This is the "approved list". Until you fill it, every LLM API request alerts, which is why the rule ships at `level: low`. Raise it to medium once the list is populated. Extend the rule's host list for providers you care about. |
| MCP/agent config modified | `Image` (suffix) | Dotfile manager, configuration management agent, internal provisioning tool, agents installed in unlisted locations | Prefer full paths over file names. See the notes below. |
| Agent bypass flags | `User` (suffix) | CI runner or dev-container accounts that run agents unattended in disposable sandboxes | Do not allowlist developers' own accounts. Bypass mode on a workstation is a policy question. |
| Agent-spawned credential access | `User` (suffix) | Infrastructure automation accounts whose agents manage kubeconfig or cloud config | Consider tuning on the parent agent and command line instead of the whole account. |
| System-prompt canary | `service.name` (allowlist) plus the token list in `…_tokens.yml` | Scheduled canary self-test service; your deployment's secret canary tokens | Keep the token filter private. The committed canary queries contain the test placeholder token `SPCANARY-7f3c9a1e5b2d`: regenerate them (`make convert`) after replacing the token filter. See the canary notes below. |

## Allowlist fields must always be present

In SQL-style backends (ES|QL, SQL databases) a filter compiles to something like `NOT field == "x"`. If an event has no `field`, the comparison is NULL, `NOT NULL` is NULL, and the event is dropped. The allowlist then hides every event that lacks the field, not just the allowlisted ones. Splunk's `NOT field="x"` does not behave this way, so the problem can go unnoticed in mixed environments.

This is why:

- the AWS filters key on `userIdentity.arn`, which every CloudTrail identity type has, rather than `userIdentity.sessionContext.sessionIssuer.arn`, which IAM users with long-term access keys (the classic LLMjacking case) do not have;
- the proxy filter keys on `src_ip` rather than `cs-username`, which unauthenticated proxies omit.

The test suite checks this: `test_sqlite_engine_agrees_with_golang_expr` replays every sample through SQLite and fails if an allowlist drops an event that lacks the filter field. When you add entries on another field, add a sample event without that field to `positive.ndjson` and run `make test`.

## Backend caveats

- **ES|QL case sensitivity is handled.** ES|QL `==`, `in`, `like`, `starts_with` and `ends_with` are case-sensitive, while Sigma is not. The committed ES|QL queries compare `to_lower(field)` against lower-cased values (`scripts/backends.py`), so upper-case AzureActivity operation names and lower-cased canary tokens match. ECS `ip` fields are the exception: they compare with `to_ip()` because `to_lower()` on an `ip` field rejects the whole query. Allowlist IP ranges with Sigma's `|cidr` modifier (emitted as `cidr_match()`), not wildcards. `to_lower()` on every comparison stops Elasticsearch from using the keyword index directly. That is fine for scheduled detections over a short lookback, but expect slower ad-hoc searches over long ranges.
- **Correlation scheduling.** The Splunk query for the multi-region rule uses `streamstats time_window=1h`, a sliding window. The ES|QL query has no time bucket. Schedule it every 5-10 minutes with a 60-minute lookback so that bursts straddling an hour boundary are counted together. Do not run it ad hoc over ranges longer than an hour: without the lookback it counts regions across the whole range and alerts on slow, legitimate multi-region use (see [testing.md](testing.md#correlation-rules-sqlite-with-an-explicit-window)).
- **Field names and data sources assumed by `pipelines/`:**

| Log source | Splunk (`pipelines/splunk/`) | ES\|QL (`pipelines/esql/`) |
|---|---|---|
| AWS CloudTrail | `sourcetype="aws:cloudtrail"`, CloudTrail field names | `logs-aws.cloudtrail-*`, ECS / `aws.cloudtrail.*` (Elastic AWS integration) |
| Proxy | CIM Web data model fields, `tag=web` | `logs-*`, ECS `url.*`, `source.ip`, `user.name` |
| Process creation / file events | Sysmon field names (Windows or Linux), `EventCode=1` / `EventCode=11`, **placeholder** `index="sysmon"` | `logs-endpoint.events.process-*` / `file-*`, ECS (Elastic Defend) |
| Azure activity | **No field mapping.** AzureActivity field names, **placeholder** `index="azure_activity"` | **No field mapping.** AzureActivity field names, all indices |
| LLM gateway | **No field mapping.** OpenTelemetry GenAI attribute names, **placeholder** `index="llm_gateway"` | **No field mapping.** OpenTelemetry GenAI attribute names, all indices |

Replace the placeholder indexes in `pipelines/splunk/endpoint.yml` and `pipelines/splunk/placeholders.yml` before scheduling the Splunk queries. For Azure and LLM gateway data, the queries only work as-is when your data uses the same field names as the samples: AzureActivity rows as exported by Log Analytics / Microsoft Sentinel, and OpenTelemetry GenAI attributes. Data from the diagnostic-settings export (`operationName`, SigmaHQ's azure/activitylogs convention), the Splunk Microsoft Cloud Services add-on or Elastic's Azure integration (`azure.activitylogs.*`) needs a field mapping added to the pipelines first.

## Rule-specific notes

- **MCP/agent config modified: exclusions are by install location.** Claude Code (native and npm), Claude Desktop, Cursor, VS Code, Windsurf and Codex are excluded by their full install paths, not by file name. Excluding any image ending in `/code` or `/claude` would let a dropped binary with that name write the files, and the samples include exactly that case. Agents installed elsewhere (portable builds, AppImages, custom prefixes) alert until you add their path to the allowlist filter. Per-user locations (`~/.local/share`, `%LOCALAPPDATA%`) remain writable by malware running as that user, so this raises the bar but does not close the gap.
- **MCP/agent config modified: Node.js trade-off.** Gemini CLI and other npm-hosted agents run as `node`, which the rule cannot tell apart from any Node.js script, so a user changing their Gemini settings alerts. Adding `/node` or `\node.exe` to the filter silences that, but it also hides a malicious npm package writing the file, which is the attack this rule exists for.
- **Agent bypass flags and config paths change quickly.** Both endpoint rules state the date and the CLI versions they were verified against (2026-09-25: Claude Code 2.1.282, Codex CLI 0.157.0, Gemini CLI 0.61.0, Copilot CLI 1.0.88). Re-check monthly with each CLI's `--help` output and update `modified`.
- **Credential access by agents.** `ls ~/.aws` does not match, while `cat ~/.aws/credentials` does. The rule looks for credential file names on the child's command line, so reading via a script file (`python read.py`) and the agents' own in-process file tools (which spawn no process) are not covered. Pair it with file-access telemetry on the credential paths. SSH public keys (`*.pub`) do not match, and only default private key names are covered. An agent running `kubectl --kubeconfig ~/.kube/config get pods` alerts. This is deliberate (see the rule's false positives), so tune it by user or host.
- **System-prompt canary.** The rule alone matches the public `SPCANARY-` prefix, which anyone can make a model print. Deploy it with `filters/llm_gateway_system_prompt_canary_in_output_tokens.yml` holding your own random or HMAC-derived tokens, and keep that file out of anything you publish. The token filter also ignores requests whose input already contained the token (a user echoing a known token is not a new leak). Its `|exists` guard keeps that exclusion from dropping every event where input content is not logged. Encoded or paraphrased leaks (base64, spaced characters, translation) are not detected.
