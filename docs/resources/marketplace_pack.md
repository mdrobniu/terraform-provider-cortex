---
page_title: "cortex_marketplace_pack Resource - cortex"
subcategory: ""
description: |-
  Installs a pack from the XSOAR Marketplace.
---

# cortex_marketplace_pack (Resource)

Installs a pack from the XSOAR Marketplace.

This resource manages the installation and lifecycle of Marketplace content packs on the XSOAR instance. Packs provide integrations, playbooks, scripts, and other content.

~> **Note:** Changing the `pack_id` attribute will destroy the existing pack installation and install a new one.

## Example Usage

### Install the latest version of a pack

```terraform
resource "cortex_marketplace_pack" "common_scripts" {
  pack_id = "CommonScripts"
}
```

### Install a specific version of a pack

```terraform
resource "cortex_marketplace_pack" "base" {
  pack_id = "Base"
  version = "1.34.20"
}
```

## Schema

### Required

- `pack_id` (String) The unique identifier of the Marketplace pack. Changing this forces a new resource to be created.

### Optional

- `version` (String) The version of the pack to install. If not specified, the latest available version is installed.

### Read-Only

- `id` (String) The identifier of the installed pack (same as pack_id).
- `name` (String) The display name of the pack as shown in the Marketplace.

## Import

Import is supported using the pack ID:

```shell
terraform import cortex_marketplace_pack.common_scripts "CommonScripts"
```
