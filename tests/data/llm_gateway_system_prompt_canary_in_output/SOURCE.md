# Sample provenance: llm_gateway_system_prompt_canary_in_output

Hand-crafted LLM gateway log records whose attribute names and message structure follow the [OpenTelemetry GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai) (Apache-2.0): `gen_ai.system_instructions`, `gen_ai.input.messages` and `gen_ai.output.messages` recorded as JSON strings, plus `gen_ai.conversation.id`, `gen_ai.usage.*` and the `service.name` resource attribute. Nested objects are used for dotted names, the way SIEMs expand them. No real prompts or conversations.

| File | Content |
|---|---|
| `positive.ndjson` | A prompt-injection style request that makes the model print its instructions, including the canary, a translation request whose output contains the canary in lower case, and a leak from an application that does not log input content (no `gen_ai.input.messages`, which is opt-in in OpenTelemetry). |
| `negative.ndjson` | Normal answers, a refusal, and a user who pastes the canary into the *input*. A user who supplies the token and gets the model to echo it (not a new leak: excluded by the token filter). The public prefix with a token that is not the deployment's (`SPCANARY-000000000000`), which anyone can make a model print. Every record carries the canary in `gen_ai.system_instructions`, which must not match. |
| `allowlisted.ndjson` | A canary self-test from the placeholder `allowlisted-canary-selftest` service. |
