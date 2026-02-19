---
page_title: "cortex_external_storage Resource - terraform-provider-cortex"
subcategory: ""
description: |-
  Manages an external storage configuration in Cortex XSOAR 8 OPP. External storage is used for backups and data archival to NFS shares or S3-compatible object stores.
---

# cortex_external_storage (Resource)

Manages an external storage configuration in Cortex XSOAR 8 OPP (On-Premise Private). External storage defines a remote storage destination used for automated backups and data archival. Supported storage types include NFS, AWS S3, and S3-compatible object stores.

Supported on XSOAR 8 OPP only. Requires session authentication (provider `ui_url`, `username`, and `password` must be configured).

~> **Note:** This resource requires session-based authentication to the XSOAR 8 OPP webapp API. Ensure the provider is configured with `ui_url`, `username`, and `password` in addition to the standard `api_url` and `api_key`.

~> **Note:** Changing the `storage_type` attribute forces replacement of the resource (destroy and recreate).

## Example Usage

### NFS Storage

```terraform
resource "cortex_external_storage" "nfs_backup" {
  name         = "nfs-backup-store"
  storage_type = "nfs"
  nfs_server   = "nfs.internal.corp"
  nfs_path     = "/exports/xsoar-backups"
}
```

### AWS S3 Storage

```terraform
resource "cortex_external_storage" "aws_backup" {
  name         = "aws-backup-store"
  storage_type = "aws"
  bucket_name  = "xsoar-backups-prod"
  region       = "us-east-1"
  access_key   = var.aws_access_key
  secret_key   = var.aws_secret_key
}
```

### S3-Compatible Storage (MinIO)

```terraform
resource "cortex_external_storage" "minio_backup" {
  name         = "minio-backup-store"
  storage_type = "s3compatible"
  bucket_name  = "xsoar-backups"
  s3_url       = "https://minio.internal.corp:9000"
  access_key   = var.minio_access_key
  secret_key   = var.minio_secret_key
}
```

### External Storage with Backup Schedule

```terraform
resource "cortex_external_storage" "backup_store" {
  name         = "prod-nfs-store"
  storage_type = "nfs"
  nfs_server   = "nfs.internal.corp"
  nfs_path     = "/exports/xsoar-backups"
}

resource "cortex_backup_schedule" "daily" {
  storage_id       = cortex_external_storage.backup_store.storage_id
  retention_period = 30
  relative_path    = "/daily"
  at_time_hour     = "03"
  at_time_minute   = "00"
}
```

## Schema

### Required

- `name` (String) The display name of the external storage configuration.
- `storage_type` (String, Forces Replacement) The type of external storage. Valid values are `nfs`, `aws`, or `s3compatible`. Changing this forces a new resource.

### Optional

- `nfs_server` (String) The hostname or IP address of the NFS server. Required when `storage_type` is `"nfs"`.
- `nfs_path` (String) The export path on the NFS server. Required when `storage_type` is `"nfs"`.
- `bucket_name` (String) The name of the S3 bucket. Required when `storage_type` is `"aws"` or `"s3compatible"`.
- `region` (String) The AWS region of the S3 bucket. Required when `storage_type` is `"aws"`.
- `access_key` (String, Sensitive) The access key for S3 authentication. Required when `storage_type` is `"aws"` or `"s3compatible"`.
- `secret_key` (String, Sensitive) The secret key for S3 authentication. Required when `storage_type` is `"aws"` or `"s3compatible"`.
- `s3_url` (String) The endpoint URL for S3-compatible storage. Required when `storage_type` is `"s3compatible"`.

### Read-Only

- `id` (String) The identifier of the external storage resource.
- `storage_id` (String) The server-assigned storage ID. Use this value when referencing the storage in other resources such as `cortex_backup_schedule`.

## Import

External storage configurations can be imported using the storage ID:

```shell
terraform import cortex_external_storage.nfs_backup <storage-id>
```
