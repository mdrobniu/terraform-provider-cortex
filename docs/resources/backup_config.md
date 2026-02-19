---
page_title: "cortex_backup_config Resource - terraform-provider-cortex"
subcategory: ""
description: |-
  Manages the backup configuration for Cortex XSOAR 6. This is a singleton resource that controls the automated backup schedule and retention policy.
---

# cortex_backup_config (Resource)

Manages the backup configuration for Cortex XSOAR 6. This is a singleton resource -- only one instance can exist per XSOAR server. It controls the automated backup schedule, retention policy, and storage path.

Supported on XSOAR 6 only.

~> **Note:** This is a singleton resource. Only one `cortex_backup_config` resource should exist in your Terraform configuration. Attempting to create multiple instances will result in conflicts.

## Example Usage

### Basic Backup Configuration

```terraform
resource "cortex_backup_config" "this" {
  enabled        = true
  schedule_cron  = "0 2 * * *"
  retention_days = 30
  path           = "/opt/xsoar/backups"
}
```

### Weekly Backups with Extended Retention

```terraform
resource "cortex_backup_config" "this" {
  enabled        = true
  schedule_cron  = "0 3 * * 0"
  retention_days = 90
  path           = "/mnt/backup/xsoar"
}
```

## Schema

### Optional

- `enabled` (Boolean) Whether automated backups are enabled. Defaults to `false`.
- `schedule_cron` (String) The cron expression defining the backup schedule. For example, `"0 2 * * *"` for daily at 2:00 AM.
- `retention_days` (Number) The number of days to retain backup files before automatic deletion.
- `path` (String) The filesystem path on the XSOAR server where backups are stored.

### Read-Only

- `id` (String) The identifier of the backup configuration. Always `"backup_config"` for this singleton resource.

## Import

The backup configuration can be imported using the literal string `backup_config`:

```shell
terraform import cortex_backup_config.this backup_config
```
