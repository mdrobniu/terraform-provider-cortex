---
page_title: "cortex_backup_schedule Resource - terraform-provider-cortex"
subcategory: ""
description: |-
  Manages a backup schedule in Cortex XSOAR 8 OPP. Backup schedules define automated backup jobs that write to external storage destinations.
---

# cortex_backup_schedule (Resource)

Manages a backup schedule in Cortex XSOAR 8 OPP (On-Premise Private). Backup schedules define automated backup jobs that write to a configured external storage destination. Each schedule specifies timing, retention, and storage path parameters.

Supported on XSOAR 8 OPP only. Requires session authentication (provider `ui_url`, `username`, and `password` must be configured).

~> **Note:** The XSOAR 8 OPP API does not support updating backup schedules. Any change to any attribute forces replacement (destroy and recreate) of the resource.

~> **Note:** This resource requires session-based authentication to the XSOAR 8 OPP webapp API. Ensure the provider is configured with `ui_url`, `username`, and `password` in addition to the standard `api_url` and `api_key`.

## Example Usage

### Daily Backup at 2:00 AM

```terraform
resource "cortex_external_storage" "nfs_store" {
  name         = "backup-nfs"
  storage_type = "nfs"
  nfs_server   = "nfs.internal.corp"
  nfs_path     = "/exports/xsoar"
}

resource "cortex_backup_schedule" "daily" {
  storage_id       = cortex_external_storage.nfs_store.storage_id
  retention_period = 30
  relative_path    = "/daily-backups"
  at_time_hour     = "02"
  at_time_minute   = "00"
}
```

### Weekly Backup with Custom Schedule

```terraform
resource "cortex_backup_schedule" "weekly" {
  storage_id       = cortex_external_storage.nfs_store.storage_id
  retention_period = 90
  relative_path    = "/weekly-backups"
  at_time_hour     = "03"
  at_time_minute   = "30"
  time_period_type = "weeks"
  time_period      = 1
}
```

### Multiple Schedules on One Storage

```terraform
resource "cortex_external_storage" "backup_store" {
  name         = "prod-backup-store"
  storage_type = "aws"
  bucket_name  = "xsoar-backups-prod"
  region       = "us-east-1"
  access_key   = var.aws_access_key
  secret_key   = var.aws_secret_key
}

resource "cortex_backup_schedule" "daily" {
  storage_id       = cortex_external_storage.backup_store.storage_id
  retention_period = 14
  relative_path    = "/daily"
  at_time_hour     = "02"
  at_time_minute   = "00"
  time_period_type = "days"
  time_period      = 1
}

resource "cortex_backup_schedule" "weekly" {
  storage_id       = cortex_external_storage.backup_store.storage_id
  retention_period = 90
  relative_path    = "/weekly"
  at_time_hour     = "04"
  at_time_minute   = "00"
  time_period_type = "weeks"
  time_period      = 1
}
```

## Schema

### Required

- `storage_id` (String, Forces Replacement) The ID of the external storage destination. Obtain this from the `storage_id` attribute of a `cortex_external_storage` resource.
- `retention_period` (Number, Forces Replacement) The number of days to retain backups before automatic deletion.
- `relative_path` (String, Forces Replacement) The subdirectory path within the external storage where backups are written.

### Optional

- `at_time_hour` (String, Forces Replacement) The hour (00-23) at which the backup runs. Defaults to `"02"`.
- `at_time_minute` (String, Forces Replacement) The minute (00-59) at which the backup runs. Defaults to `"00"`.
- `time_period_type` (String, Forces Replacement) The unit for the backup frequency. Valid values include `"days"` and `"weeks"`.
- `time_period` (Number, Forces Replacement) The interval between backups, in units of `time_period_type`. For example, `time_period = 1` with `time_period_type = "days"` means a daily backup.

### Read-Only

- `id` (String) The identifier of the backup schedule resource.
- `schedule_id` (String) The server-assigned schedule ID.

## Import

Backup schedules can be imported using the schedule ID:

```shell
terraform import cortex_backup_schedule.daily <schedule-id>
```
