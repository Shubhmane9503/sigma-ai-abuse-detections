# Sample provenance: azure_ai_services_key_listed_or_regenerated

Hand-crafted records in the Azure Monitor [AzureActivity table schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azureactivity) (Log Analytics / Microsoft Sentinel). No third-party data. Subscription and tenant IDs are all-zero placeholders, users use `example.com`, and service principal object IDs are `00000000-0000-0000-0000-...` placeholders.

| File | Content |
|---|---|
| `positive.ndjson` | Successful `listKeys` by a user (operation name in upper case, as the AzureActivity table often records it) and successful `regenerateKey` by a service principal on a `Microsoft.CognitiveServices/accounts` resource. |
| `negative.ndjson` | `listKeys` with status `Start` and `Failure`, other Cognitive Services operations (`accounts/write`, `deployments/write`), and `listKeys` on a storage account (a different resource provider). |
| `allowlisted.ndjson` | `listKeys` and `regenerateKey` by the two placeholder principals in the allowlist filter. |
