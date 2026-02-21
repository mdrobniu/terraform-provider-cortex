---
page_title: "cortex_collector_policies Data Source - terraform-provider-cortex"
subcategory: ""
description: |-
  Retrieves a list of all collector policies in XSIAM.
---

# cortex_collector_policies (Data Source)

Retrieves a read-only list of all collector policies configured in XSIAM. Collector policies define how data is collected from various sources and which broker VMs or agents are targeted for collection. Each policy specifies the platform, priority, and enablement status.

~> **Note:** This data source is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

```terraform
data "cortex_collector_policies" "all" {}

output "policy_names" {
  value = data.cortex_collector_policies.all.policies[*].name
}

output "enabled_policies" {
  value = [
    for p in data.cortex_collector_policies.all.policies : p.name
    if p.is_enabled
  ]
}
```

## Schema

### Read-Only

- `policies` (List of Object) The list of all collector policies in XSIAM.
  - `id` (String) The unique identifier of the collector policy.
  - `name` (String) The display name of the collector policy.
  - `platform` (String) The target platform for this policy (e.g., `WINDOWS`, `LINUX`, `MAC`).
  - `priority` (Number) The evaluation priority of the policy. Lower values indicate higher priority.
  - `is_enabled` (Boolean) Whether the collector policy is currently enabled.
  - `target_id` (Number) The identifier of the target broker VM or agent group associated with this policy.
  - `standard_id` (Number) The identifier of the collection standard used by this policy.
