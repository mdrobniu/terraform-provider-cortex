---
page_title: "cortex_agent_group Resource - cortex"
subcategory: ""
description: |-
  Manages agent groups in XSIAM.
---

# cortex_agent_group (Resource)

Manages agent groups in XSIAM. Agent groups organize endpoints into logical collections for policy assignment, reporting, and management. Groups can be either dynamic (membership determined by a filter expression) or static (membership managed manually).

The group `type` is immutable -- switching between DYNAMIC and STATIC requires destroying and recreating the resource.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

### Dynamic Group

```terraform
resource "cortex_agent_group" "windows_servers" {
  name        = "Windows Servers"
  description = "All Windows Server endpoints"
  type        = "DYNAMIC"

  filter = jsonencode({
    and = [
      { field = "os_type", operator = "eq", value = "Windows" },
      { field = "os_version", operator = "contains", value = "Server" }
    ]
  })
}
```

### Static Group

```terraform
resource "cortex_agent_group" "vip_endpoints" {
  name        = "VIP Endpoints"
  description = "Manually managed group for executive endpoints"
  type        = "STATIC"
}
```

## Argument Reference

* `name` - (Required) The display name of the agent group.
* `description` - (Optional) A description of the agent group's purpose.
* `type` - (Required, Forces new resource) The group membership type. Valid values are `DYNAMIC` (membership determined by filter) or `STATIC` (membership managed manually). Changing this value will destroy and recreate the resource.
* `filter` - (Optional) A JSON-encoded filter expression that determines dynamic group membership. Only applicable when `type` is `DYNAMIC`.

## Attributes Reference

* `group_id` - The unique identifier assigned to the agent group by XSIAM.
* `endpoint_count` - The current number of agents in the group.

## Import

Agent groups can be imported using their group ID:

```shell
terraform import cortex_agent_group.windows_servers 12345
```
