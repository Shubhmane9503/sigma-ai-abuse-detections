# Sample provenance: proxy_llm_api_unapproved_client

Hand-crafted web proxy events using the Sigma proxy taxonomy (`cs-host`, `c-uri`, `src_ip`, `cs-username`, ...). No third-party data. Internal addresses are RFC 1918, other addresses are RFC 5737 documentation ranges, and user names are fictitious.

| File | Content |
|---|---|
| `positive.ndjson` | API calls to OpenAI, Anthropic, Google Gemini, an Azure OpenAI resource (`*.openai.azure.com`) and OpenRouter from non-approved hosts. The OpenRouter event has no `cs-username` field at all, as with unauthenticated proxies. Also a CONNECT to `api.openai.com:443`, the Amazon Bedrock runtime, a regional Vertex AI endpoint, the Hugging Face router and a Hugging Face dedicated endpoint over CONNECT. |
| `negative.ndjson` | Consumer chat UIs (`chatgpt.com`, `claude.ai`), a vendor marketing site, an unrelated API, a status page, a look-alike host `api.openai.com.cdn.example.net` that must not match the exact API hostnames, the Bedrock control plane (`bedrock.<region>`), the Hugging Face website, and S3 and Cloud Storage traffic. |
| `allowlisted.ndjson` | LLM API calls from the placeholder approved host `192.0.2.10`, one without a `cs-username` field. |
