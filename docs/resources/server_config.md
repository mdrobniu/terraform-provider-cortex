---
page_title: "cortex_server_config Resource - cortex"
subcategory: ""
description: |-
  Manages an individual key-value pair in the XSOAR server configuration.
---

# cortex_server_config (Resource)

Manages an individual key-value pair in the XSOAR server configuration.

Server configuration keys control various aspects of the XSOAR platform behavior, such as session timeouts, notification settings, and feature flags.

~> **Note:** Changing the `key` attribute will destroy the existing config entry and create a new one.

## Example Usage

```terraform
resource "cortex_server_config" "session_timeout" {
  key   = "session.timeout"
  value = "60"
}

resource "cortex_server_config" "max_incidents" {
  key   = "incidents.maxNumberOfIncidents"
  value = "10000"
}
```

## Schema

### Required

- `key` (String) The server configuration key name. Changing this forces a new resource to be created.
- `value` (String) The value for the configuration key.

### Read-Only

- `id` (String) The identifier of the config entry (same as key).

## Import

Import is supported using the configuration key:

```shell
terraform import cortex_server_config.session_timeout "session.timeout"
```
