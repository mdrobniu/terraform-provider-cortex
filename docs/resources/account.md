---
page_title: "cortex_account Resource - terraform-provider-cortex"
subcategory: ""
description: |-
  Manages a multi-tenant account in Cortex XSOAR 6. Accounts provide isolated tenant environments within a shared XSOAR deployment.
---

# cortex_account (Resource)

Manages a multi-tenant account in Cortex XSOAR 6. Accounts provide isolated tenant environments within a shared XSOAR deployment, each with their own incidents, indicators, playbooks, and configurations. Accounts are assigned to HA groups (host groups) which determine the underlying infrastructure.

Supported on XSOAR 6 only.

~> **Note:** The `name` attribute specifies the account name without the `acc_` prefix. XSOAR automatically prepends `acc_` to create the full account identifier. Changing the `name` forces replacement of the resource.

## Example Usage

### Basic Account

```terraform
resource "cortex_ha_group" "production" {
  name                 = "production-cluster"
  elasticsearch_url    = "https://es-prod.internal:9200"
  elastic_index_prefix = "xsoar-prod"
}

resource "cortex_account" "tenant_alpha" {
  name            = "tenant-alpha"
  host_group_name = cortex_ha_group.production.name
}
```

### Account with Custom Roles and Propagation Labels

```terraform
resource "cortex_account" "tenant_beta" {
  name            = "tenant-beta"
  host_group_name = cortex_ha_group.production.name

  account_roles      = ["Administrator", "Analyst"]
  propagation_labels = ["all", "tier1"]
}
```

### Multiple Tenant Accounts

```terraform
resource "cortex_ha_group" "shared" {
  name                 = "shared-cluster"
  elasticsearch_url    = "https://es-shared.internal:9200"
  elastic_index_prefix = "xsoar-shared"
}

locals {
  tenants = {
    alpha = { roles = ["Administrator"] }
    beta  = { roles = ["Administrator", "Analyst"] }
    gamma = { roles = ["Administrator", "Read-Only"] }
  }
}

resource "cortex_account" "tenants" {
  for_each = local.tenants

  name            = each.key
  host_group_name = cortex_ha_group.shared.name
  account_roles   = each.value.roles
}
```

## Schema

### Required

- `name` (String, Forces Replacement) The account name without the `acc_` prefix. XSOAR automatically prepends `acc_` to form the full account identifier. Changing this forces a new resource.
- `host_group_name` (String) The name of the HA group (host group) to assign this account to.

### Optional

- `account_roles` (List of String) The list of roles assigned to the account. Defaults to `["Administrator"]` if not specified.
- `propagation_labels` (List of String) The list of propagation labels for the account. Propagation labels control which content packs and configurations are propagated to this tenant.

### Read-Only

- `id` (String) The identifier of the account.
- `host_group_id` (String) The ID of the HA group this account belongs to.

## Import

Accounts can be imported using the account name (without the `acc_` prefix):

```shell
terraform import cortex_account.tenant_alpha tenant-alpha
```
