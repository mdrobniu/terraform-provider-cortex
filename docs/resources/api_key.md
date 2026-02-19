---
page_title: "cortex_api_key Resource - cortex"
subcategory: ""
description: |-
  Manages an API key for XSOAR programmatic access.
---

# cortex_api_key (Resource)

Manages an API key for XSOAR programmatic access.

API keys are used for authenticating external tools and scripts against the XSOAR API. The generated key value is only available at creation time and is stored in the Terraform state as a sensitive value.

~> **Note:** The `key_value` attribute is sensitive and only available after initial creation. If the state is lost, the key cannot be recovered and must be recreated.

~> **Note (XSOAR 8 SaaS):** This resource is **not available** on XSOAR 8 SaaS deployments. API keys for SaaS instances are managed through the Cortex Hub.

## Example Usage

```terraform
resource "cortex_api_key" "automation" {
  name = "automation-service"
}

output "api_key_value" {
  value     = cortex_api_key.automation.key_value
  sensitive = true
}
```

## Schema

### Required

- `name` (String) The display name of the API key. Changing this forces a new resource to be created.

### Read-Only

- `id` (String) The identifier of the API key.
- `key_value` (String, Sensitive) The generated API key value. Only available at creation time.

## Import

Import is supported using the API key name:

```shell
terraform import cortex_api_key.automation "automation-service"
```

~> **Note:** Importing an API key will not populate the `key_value` attribute, as XSOAR does not expose existing key values through the API.
