---
page_title: "cortex_custom_status Resource - cortex"
subcategory: ""
description: |-
  Manages custom incident statuses in XSIAM.
---

# cortex_custom_status (Resource)

Manages custom incident statuses in XSIAM. Custom statuses extend the default incident lifecycle with organization-specific status values such as "Awaiting Approval", "In Review", or "Escalated".

The `pretty_name` and `status_type` are immutable after creation -- changing either requires destroying and recreating the resource. The `enum_name` is a system-generated internal identifier derived from the pretty name.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

```terraform
resource "cortex_custom_status" "awaiting_approval" {
  pretty_name = "Awaiting Approval"
  status_type = "incident"
  priority    = 50
}

resource "cortex_custom_status" "escalated" {
  pretty_name = "Escalated"
  status_type = "alert"
  priority    = 60
}
```

## Argument Reference

* `pretty_name` - (Required, Forces new resource) The display name of the custom status. Changing this value will destroy and recreate the resource.
* `status_type` - (Required, Forces new resource) The type of entity this status applies to (e.g., `incident`, `alert`). Changing this value will destroy and recreate the resource.
* `priority` - (Optional) The sort priority of the status in the status list. Higher values appear later in the list.

## Attributes Reference

* `enum_name` - The system-generated internal identifier for this status, derived from the pretty name.
* `can_delete` - Whether this custom status can be deleted. System statuses cannot be deleted.

## Import

Custom statuses can be imported using their `enum_name`:

```shell
terraform import cortex_custom_status.awaiting_approval AWAITING_APPROVAL
```
