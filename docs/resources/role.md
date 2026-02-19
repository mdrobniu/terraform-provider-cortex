---
page_title: "cortex_role Resource - cortex"
subcategory: ""
description: |-
  Manages a user role in XSOAR.
---

# cortex_role (Resource)

Manages a user role in XSOAR.

Roles define the set of permissions granted to users. Each role contains a JSON-encoded permissions object that specifies which actions users with that role can perform.

~> **Note (XSOAR 8):** On XSOAR 8, roles are managed at the XDR platform level and are **read-only** through the XSOAR API. This resource is only fully functional on XSOAR 6.

## Example Usage

```terraform
resource "cortex_role" "analyst" {
  name = "SOC Analyst"

  permissions = jsonencode({
    dempiAdmin          = false
    demistoWrite        = true
    demistoRead         = true
    investigationCreate = true
    investigationRead   = true
    playgroundRun       = true
  })
}

resource "cortex_role" "readonly" {
  name = "Read Only"

  permissions = jsonencode({
    demistoRead     = true
    demistoWrite    = false
    dempiAdmin      = false
  })
}
```

## Schema

### Required

- `name` (String) The name of the role.
- `permissions` (String) A JSON-encoded string representing the role permissions object.

### Read-Only

- `id` (String) The identifier of the role (same as name).
- `version` (Number) The internal version of the role, used for optimistic locking.

## Import

Import is supported using the role name:

```shell
terraform import cortex_role.analyst "SOC Analyst"
```
