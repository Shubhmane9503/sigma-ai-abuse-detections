# Sample provenance: aws_bedrock_model_access_enabled

Raw CloudTrail JSON records.

| File | Origin |
|---|---|
| `positive.ndjson` | Lines 1-3: the `PutUseCaseForModelAccess`, `CreateFoundationModelAgreement` and `PutFoundationModelEntitlement` events from the Stratus Red Team detonation log for `aws.impact.bedrock-invoke-model` ([docs/detonation-logs/aws.impact.bedrock-invoke-model.json](https://github.com/DataDog/stratus-red-team/blob/17707ea98cbc9c77eb123dbcec49ad96acde72ca/docs/detonation-logs/aws.impact.bedrock-invoke-model.json), Apache-2.0). Line 4: derived from the Stratus `PutFoundationModelEntitlement` event, with the identity replaced by an IAM user holding a long-term access key (no `sessionContext`). This covers leaked-key LLMjacking and keeps the allowlist filter honest about absent fields. |
| `negative.ndjson` | The other 12 events of the same Stratus log: `GetFoundationModelAvailability`, `ListFoundationModelAgreementOffers` and `InvokeModel`. |
| `allowlisted.ndjson` | Derived from the Stratus `CreateFoundationModelAgreement` event, re-attributed to the placeholder role in the allowlist filter. |

Scrubbing (`scripts/scrub_samples.py`): account ID replaced with `111122223333`, access key ID with `ASIAIOSFODNN7EXAMPLE`, role principal ID with `AROAEXAMPLEROLEID0001`, source IP with `203.0.113.10`. Stratus had already anonymised the region (`megov-northeast-1r`), and it was kept as is.
