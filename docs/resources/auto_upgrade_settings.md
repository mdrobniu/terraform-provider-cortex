---
page_title: "cortex_auto_upgrade_settings Resource - cortex"
subcategory: ""
description: |-
  Manages agent auto-upgrade settings in XSIAM.
---

# cortex_auto_upgrade_settings (Resource)

Manages the singleton agent auto-upgrade settings in XSIAM. This resource controls the maintenance window during which endpoint agents are automatically upgraded, including the schedule (days and time window) and the number of agents upgraded per batch.

This is a singleton resource -- only one `cortex_auto_upgrade_settings` resource should exist per XSIAM tenant. Both create and update operations set the full configuration. Destroying this resource is a no-op since the auto-upgrade settings cannot be deleted from XSIAM.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

~> **Important:** The GET endpoint may return HTTP 500 on some XSIAM instances. The provider handles this gracefully by keeping the existing Terraform state unchanged rather than failing the plan.

## Example Usage

```terraform
resource "cortex_auto_upgrade_settings" "config" {
  start_time = "02:00"
  end_time   = "06:00"
  days       = ["Monday", "Wednesday", "Friday"]
  batch_size = 100
}
```

### Minimal Configuration

```terraform
resource "cortex_auto_upgrade_settings" "config" {
  batch_size = 50
}
```

## Argument Reference

* `batch_size` - (Required) The number of agents to upgrade per batch during the maintenance window.
* `start_time` - (Optional) The start time of the upgrade window in 24-hour format (e.g., `"02:00"`). If not specified, the existing value from XSIAM is preserved.
* `end_time` - (Optional) The end time of the upgrade window in 24-hour format (e.g., `"06:00"`). If not specified, the existing value from XSIAM is preserved.
* `days` - (Optional) A list of days of the week during which auto-upgrades are allowed. Valid values are `"Sunday"`, `"Monday"`, `"Tuesday"`, `"Wednesday"`, `"Thursday"`, `"Friday"`, `"Saturday"`. If not specified, the existing value from XSIAM is preserved.

## Attributes Reference

All arguments are also exported as attributes.

## Import

The auto-upgrade settings are a singleton and can be imported using the literal string `auto_upgrade_settings`:

```shell
terraform import cortex_auto_upgrade_settings.config auto_upgrade_settings
```
