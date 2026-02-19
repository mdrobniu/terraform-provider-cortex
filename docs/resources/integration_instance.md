---
page_title: "cortex_integration_instance Resource - cortex"
subcategory: ""
description: |-
  Manages an integration instance in XSOAR.
---

# cortex_integration_instance (Resource)

Manages an integration instance in XSOAR.

Integration instances are configured connections to external services and tools. Each instance is based on an integration definition (typically installed via a Marketplace pack) and holds the connection parameters such as API keys, URLs, and credentials.

~> **Note:** Changing the `integration_name` attribute will destroy the existing instance and create a new one.

## Example Usage

### Basic integration instance

```terraform
resource "cortex_integration_instance" "slack" {
  name             = "Slack-Production"
  integration_name = "SlackV3"
  enabled          = true

  config = {
    bot_token  = "xoxb-example-token"
    app_token  = "xapp-example-token"
    proxy      = "false"
    unsecure   = "false"
  }
}
```

### Integration instance with engine and mappers

```terraform
resource "cortex_integration_instance" "qradar" {
  name             = "QRadar-Main"
  integration_name = "QRadar_v3"
  enabled          = true

  config = {
    server  = "https://qradar.example.com"
    token   = "my-api-token"
    proxy   = "false"
  }

  engine               = "d2-engine-01"
  incoming_mapper_id   = "QRadar-mapper-incoming"
  outgoing_mapper_id   = "QRadar-mapper-outgoing"
  propagation_labels   = ["production", "soc"]
  log_level            = "debug"
}
```

## Schema

### Required

- `name` (String) The display name of the integration instance.
- `integration_name` (String) The identifier of the base integration definition. Changing this forces a new resource to be created.
- `config` (Map of String) A map of configuration key-value pairs for the integration instance. The available keys depend on the integration definition.

### Optional

- `enabled` (Boolean) Whether the integration instance is enabled. Defaults to `true`.
- `propagation_labels` (List of String) A list of propagation labels to associate with the instance.
- `engine` (String) The name of the d2 engine to route requests through.
- `engine_group` (String) The name of the engine group to route requests through.
- `incoming_mapper_id` (String) The ID of the incoming mapper to use.
- `outgoing_mapper_id` (String) The ID of the outgoing mapper to use.
- `mapping_id` (String) The ID of the mapping to use.
- `log_level` (String) The log level for the integration instance (e.g., `"debug"`, `"info"`, `"error"`).

### Read-Only

- `id` (String) The unique identifier of the integration instance.

## Import

Import is supported using the instance ID:

```shell
terraform import cortex_integration_instance.slack "Slack-Production"
```
