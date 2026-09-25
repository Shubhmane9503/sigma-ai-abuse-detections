# Sample provenance: proc_creation_ai_coding_agent_approval_bypass

Sysmon-style process creation events (`Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `User`).

| File | Origin |
|---|---|
| `positive.ndjson` | Lines 1-3: command lines taken verbatim from the auditd `PROCTITLE` records in Splunk attack_data [`datasets/attack_techniques/T1480/ai_cli_override/gemini_yolo.log`](https://github.com/splunk/attack_data/blob/b4573ed3b6bf05473b01048dd36380dbd52288c0/datasets/attack_techniques/T1480/ai_cli_override/gemini_yolo.log) (Apache-2.0). They show the Gemini CLI started with `--yolo` and `-yolo`. The records were reshaped into process creation events (image `node`, which is how the npm-installed CLI runs), keeping the original timestamps, audit serial numbers as process IDs, and the `ubuntu` lab user. Lines 4-14: hand-crafted, one per bypass option verified on 2026-09-25 from the `--help` output of Claude Code 2.1.282, Codex CLI 0.157.0, Gemini CLI 0.61.0 and GitHub Copilot CLI 1.0.88. |
| `negative.ndjson` | Line 1: the same Gemini command line from the Splunk dataset without the flag. Remaining lines: hand-crafted normal agent launches (`--permission-mode acceptEdits` and `plan`, Codex `workspace-write` with `on-request`, `--full-auto`, Gemini `auto_edit`, Copilot without `--allow-all`), plus `-y`, `--yolo` and `--allow-all` passed to non-agent programs. |
| `allowlisted.ndjson` | Codex bypass mode run by the placeholder CI sandbox account. |
