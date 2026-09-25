# Sample provenance: aws_bedrock_invoke_model_multi_region

Raw CloudTrail JSON records. Every event is derived from the `InvokeModel` (and, for one negative group, `GetFoundationModelAvailability`) event in the Stratus Red Team detonation log for `aws.impact.bedrock-invoke-model` ([source](https://github.com/DataDog/stratus-red-team/blob/17707ea98cbc9c77eb123dbcec49ad96acde72ca/docs/detonation-logs/aws.impact.bedrock-invoke-model.json), Apache-2.0). Region, time, event name, identity and IDs were changed to build the scenarios below. The record structure is unchanged.

| File | Scenario |
|---|---|
| `positive.ndjson` | `test-role/cli` (the Stratus identity) invokes models in us-east-1, us-west-2 and eu-central-1 within 36 minutes, mixing `InvokeModel`, `InvokeModelWithResponseStream` and `Converse`. IAM user `ci-deployer` (long-term key, no `sessionContext`) invokes in us-east-1, ap-northeast-1 and eu-west-3 within 20 minutes. Both groups must alert. |
| `negative.ndjson` | (1) `app-prod`: two regions only. (2) **Window case** `batch-eval`: three regions within 61 minutes (01:00, 01:35, 02:01), so no 1 hour window holds all three. This alerts if the timespan is ignored or widened by even a few minutes. (3) Three identities, one region each, at the same time. (4) `explorer`: three regions within minutes, but only `GetFoundationModelAvailability` (not inference). |
| `allowlisted.ndjson` | The placeholder allowlisted role invokes models in three regions within 20 minutes. It alerts without the filter and not with it. |

Scrubbing: as for `aws_bedrock_model_access_enabled` (account `111122223333`, example access keys, documentation IP ranges).
