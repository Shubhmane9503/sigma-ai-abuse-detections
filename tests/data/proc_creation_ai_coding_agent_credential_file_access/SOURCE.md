# Sample provenance: proc_creation_ai_coding_agent_credential_file_access

Hand-crafted Sysmon-style process creation events. No third-party data. Parent images and command lines follow the install layouts checked on 2026-09-25 (native Claude Code under `claude/versions/`, Codex native binary, Gemini CLI and Copilot CLI under Node.js).

| File | Content |
|---|---|
| `positive.ndjson` | Shells or readers spawned by Claude Code, Codex, Gemini CLI and Copilot CLI reading AWS, SSH, kubeconfig, Azure MSAL, gcloud ADC, git and npm credential files, including one piping the file to an external collector (`collector.example.net`), and one reading a private key together with its `.pub`. |
| `negative.ndjson` | Agent children that do not touch credentials (including `ls ~/.aws` and reading a public key `id_ed25519.pub`), and ordinary user shells, `ssh` and `kubectl` using credential files outside any agent. |
| `allowlisted.ndjson` | An agent child reading kubeconfig under the placeholder infrastructure automation account. |
