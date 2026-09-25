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
| Bedrock model access enabled | `userIdentity.arn` prefix | `arn:aws:sts::<acct>:assumed-role/<platform-admin-role>/`, IaC deployer role | Enabling model access is rare, so keep the list short. |
| Bedrock multi-region invocation | `userIdentity.arn` prefix (applied to the base rule) | Multi-region failover services, model evaluation jobs | Sigma filters cannot target correlation rules, so this filter removes the identity's events before counting. |
| Azure AI keys listed/regenerated | `Caller` | Key-rotation automation, deployment pipelines, app managed identities (object IDs) | The Azure portal calls `listKeys` when someone opens *Keys and Endpoint*, so administrators viewing keys will alert. |
| Unapproved LLM API use | `src_ip` | AI gateway, sanctioned application servers, developer VDI ranges | This is the "approved list". Until you fill it, every LLM API request alerts. Extend the rule's host list for providers you care about. |
| MCP/agent config modified | `Image` (suffix) | Dotfile manager, configuration management agent, internal provisioning tool | See the Node.js trade-off below. |
| Agent bypass flags | `User` (suffix) | CI runner or dev-container accounts that run agents unattended in disposable sandboxes | Do not allowlist developers' own accounts. Bypass mode on a workstation is a policy question. |
| Agent-spawned credential access | `User` (suffix) | Infrastructure automation accounts whose agents manage kubeconfig or cloud config | Consider tuning on the parent agent and command line instead of the whole account. |
| System-prompt canary | `service.name` | Scheduled canary self-test service | Plant tokens with the `SPCANARY-` prefix (or change the prefix in the rule). |

## Allowlist fields must always be present

In SQL-style backends (ES|QL, SQL databases) a filter compiles to something like `NOT field == "x"`. If an event has no `field`, the comparison is NULL, `NOT NULL` is NULL, and the event is dropped. The allowlist then hides every event that lacks the field, not just the allowlisted ones. Splunk's `NOT field="x"` does not behave this way, so the problem can go unnoticed in mixed environments.

This is why:

- the AWS filters key on `userIdentity.arn`, which every CloudTrail identity type has, rather than `userIdentity.sessionContext.sessionIssuer.arn`, which IAM users with long-term access keys (the classic LLMjacking case) do not have;
- the proxy filter keys on `src_ip` rather than `cs-username`, which unauthenticated proxies omit.

The test suite checks this: `test_sqlite_engine_agrees_with_golang_expr` replays every sample through SQLite and fails if an allowlist drops an event that lacks the filter field. When you add entries on another field, add a sample event without that field to `positive.ndjson` and run `make test`.

## Backend caveats

- **ES|QL is case-sensitive.** Sigma values match case-insensitively. The ES|QL backend emits `==`, `in (...)` and `like`, which are case-sensitive. The Azure AzureActivity table often records operation names in upper case (`MICROSOFT.COGNITIVESERVICES/ACCOUNTS/LISTKEYS/ACTION`), and the rule's mixed-case values will not match those events in ES|QL. Check how your data is cased, or normalise it at ingest, before relying on the ES|QL output. Splunk, the golang_expr tests and the SQLite tests are case-insensitive.
- **Correlation windows** in Splunk and ES|QL are fixed hourly buckets, not sliding windows (see [testing.md](testing.md#correlation-rules-sqlite-with-an-explicit-window)).
- **Field names and data sources assumed by `pipelines/`:**

| Log source | Splunk (`pipelines/splunk/`) | ES\|QL (`pipelines/esql/`) |
|---|---|---|
| AWS CloudTrail | `sourcetype="aws:cloudtrail"`, CloudTrail field names | `logs-aws.cloudtrail-*`, ECS / `aws.cloudtrail.*` (Elastic AWS integration) |
| Proxy | CIM Web data model fields, `tag=web` | `logs-*`, ECS `url.*`, `source.ip`, `user.name` |
| Process creation / file events | Sysmon field names (Windows or Linux), no source condition | `logs-endpoint.events.process-*` / `file-*`, ECS (Elastic Defend) |
| Azure activity | AzureActivity field names, no source condition | AzureActivity field names, all indices |
| LLM gateway | OpenTelemetry GenAI attribute names, no source condition | OpenTelemetry GenAI attribute names, all indices |

Where no source condition is set, add your own index or sourcetype restriction to the pipeline (an `add_condition` or `set_state: index` entry) before scheduling the query.

## Rule-specific notes

- **MCP/agent config modified, Node.js trade-off.** Claude Code (native binary), Claude Desktop, Cursor, VS Code, Windsurf and Codex are excluded by image in the rule. Gemini CLI and other npm-hosted agents run as `node`, which the rule cannot tell apart from any Node.js script, so a user changing their Gemini settings alerts. Adding `/node` or `\node.exe` to the filter silences that, but it also hides a malicious npm package writing the file, which is the attack this rule exists for.
- **Agent bypass flags and config paths change quickly.** Both endpoint rules state the date and the CLI versions they were verified against (2026-09-25: Claude Code 2.1.282, Codex CLI 0.157.0, Gemini CLI 0.61.0, Copilot CLI 1.0.88). Re-check monthly with each CLI's `--help` output and update `modified`.
- **Credential access by agents.** `ls ~/.aws` does not match, while `cat ~/.aws/credentials` does. The rule looks for credential file names on the child's command line, so reading via a script file (`python read.py`) is not covered. Pair it with file-access telemetry where available.
