---
page_title: "cortex_collector_group Resource - cortex"
subcategory: ""
description: |-
  Manages XDR collector groups in XSIAM.
---

# cortex_collector_group (Resource)

Manages XDR collector groups in XSIAM. Collector groups organize data collection endpoints into logical groupings for management and policy assignment. Groups can be either dynamic (membership determined by a filter expression) or static (membership managed manually).

This resource does not support in-place updates. Any change to the group configuration will trigger a delete and recreate cycle, since the XSIAM API does not provide an update endpoint for collector groups.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

~> **Important:** All mutable attributes force resource replacement. Changing any attribute will destroy the existing group and create a new one.

## Example Usage

### Dynamic Group

```terraform
resource "cortex_collector_group" "linux_collectors" {
  name        = "Linux Collectors"
  description = "All Linux-based data collectors"
  type        = "DYNAMIC"

  filter = jsonencode({
    and = [
      { field = "os_type", operator = "eq", value = "Linux" }
    ]
  })
}
```

### Static Group

```terraform
resource "cortex_collector_group" "dmz_collectors" {
  name        = "DMZ Collectors"
  description = "Manually assigned collectors in the DMZ"
  type        = "STATIC"
}
```

## Argument Reference

* `name` - (Required, Forces new resource) The display name of the collector group.
* `type` - (Required, Forces new resource) The group membership type. Valid values are `DYNAMIC` (membership determined by filter) or `STATIC` (membership managed manually).
* `description` - (Optional, Forces new resource) A description of the collector group's purpose.
* `filter` - (Optional, Forces new resource) A JSON-encoded filter expression that determines dynamic group membership. Must be valid JSON if provided. Only applicable when `type` is `DYNAMIC`. For `STATIC` groups, omit this attribute or use an empty filter.

## Attributes Reference

* `group_id` - The unique numeric identifier assigned to the collector group by XSIAM.
* `endpoint_count` - The current number of collectors in the group.
* `created_by` - The user who created the collector group.
* `modified_by` - The user who last modified the collector group.

## Import

Collector groups can be imported using their group ID:

```shell
terraform import cortex_collector_group.linux_collectors 12345
```
