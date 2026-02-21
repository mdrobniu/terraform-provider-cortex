---
page_title: "cortex_asm_asset_removal Resource - cortex"
subcategory: ""
description: |-
  Performs bulk ASM asset removal in XSIAM.
---

# cortex_asm_asset_removal (Resource)

Performs bulk Attack Surface Management (ASM) asset removal in XSIAM. This resource removes specified assets from the external attack surface inventory when created. It is a fire-and-forget operation -- assets are removed on `terraform apply` and the removal cannot be undone.

All attributes force resource replacement. Destroying this resource is a no-op since asset removal is irreversible and there is no restore API.

!> **Warning:** Asset removal is **irreversible**. Running `terraform destroy` will NOT restore removed assets. Removed assets will no longer appear in the ASM inventory and must be re-discovered through a new scan if needed. Use with extreme caution.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

### Remove a Single Domain

```terraform
resource "cortex_asm_asset_removal" "stale_domain" {
  assets {
    asset_type = "Domain"
    asset_name = "old.example.com"
  }
}
```

### Remove Multiple Assets

```terraform
resource "cortex_asm_asset_removal" "cleanup" {
  assets {
    asset_type = "Domain"
    asset_name = "decommissioned.example.com"
  }

  assets {
    asset_type = "IP_RANGE"
    asset_name = "192.168.1.0/24"
  }

  assets {
    asset_type = "Certificate"
    asset_name = "CN=old-cert.example.com"
  }
}
```

### Using Dynamic Blocks

```terraform
variable "stale_domains" {
  type    = list(string)
  default = ["old1.example.com", "old2.example.com", "old3.example.com"]
}

resource "cortex_asm_asset_removal" "stale" {
  dynamic "assets" {
    for_each = var.stale_domains
    content {
      asset_type = "Domain"
      asset_name = assets.value
    }
  }
}
```

## Argument Reference

* `assets` - (Required, Forces new resource) One or more asset blocks defining the assets to remove. Each block supports:
  * `asset_type` - (Required) The type of asset to remove. Valid values are `Domain`, `IP_RANGE`, or `Certificate`.
  * `asset_name` - (Required) The identifier of the asset to remove (e.g., a domain name, CIDR range, or certificate CN).

## Attributes Reference

* `removed_assets` - A list of asset names that were successfully removed.
* `errors` - A list of error messages for any assets that could not be removed.

## Import

Import is not supported for this resource since asset removal is a one-time irreversible operation.
