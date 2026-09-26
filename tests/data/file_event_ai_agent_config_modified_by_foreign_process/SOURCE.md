# Sample provenance: file_event_ai_agent_config_modified_by_foreign_process

Hand-crafted Sysmon-style file creation events (`EventID` 11, `Image`, `TargetFilename`, `User`) for Linux, macOS and Windows. No third-party data. Agent image paths follow the real install layouts checked on 2026-09-25: the Claude Code native installer (`~/.local/share/claude/versions/<version>`), the npm platform package (`@anthropic-ai/claude-code-linux-x64/claude`), the Codex npm vendor binary, and the Cursor and VS Code app bundles.

| File | Content |
|---|---|
| `positive.ndjson` | Python, an unknown Windows executable, zsh, curl, PowerShell and node writing Claude Code, Claude Desktop, Cursor, project `.mcp.json`, Codex and Gemini configuration files. Two spoofed binaries named `code` and `claude` outside any agent install location, which the old basename exclusion would have let through. |
| `negative.ndjson` | The agents themselves writing their own configuration (native and npm Claude Code, Claude Desktop, Cursor, the VS Code extension host, Codex), plus non-agent processes writing unrelated files with similar names. |
| `allowlisted.ndjson` | The placeholder approved configuration manager writing `.claude/settings.json`. |
