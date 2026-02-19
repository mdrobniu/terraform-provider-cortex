---
page_title: "cortex_exclusion_list Resource - terraform-provider-cortex"
subcategory: ""
description: |-
  Manages an exclusion list entry in Cortex XSOAR. Exclusion lists prevent specified indicators (IPs, domains, regex patterns) from being flagged as malicious.
---

# cortex_exclusion_list (Resource)

Manages an exclusion list entry in Cortex XSOAR. Exclusion lists (also known as whitelists) prevent specified indicators from being created or flagged as malicious. This is useful for excluding known-good internal IPs, trusted domains, or patterns that would otherwise generate false positives.

Supported on XSOAR 6, XSOAR 8 OPP, and XSOAR 8 SaaS.

~> **Note:** Changing the `value` or `type` attributes forces replacement of the resource (destroy and recreate).

## Example Usage

### CIDR Range Exclusion

```terraform
resource "cortex_exclusion_list" "internal_network" {
  value  = "10.0.0.0/8"
  type   = "CIDR"
  reason = "Internal network"
}
```

### Domain Exclusion

```terraform
resource "cortex_exclusion_list" "trusted_domain" {
  value  = "example.com"
  type   = "standard"
  reason = "Company domain - trusted"
}
```

### Regex Pattern Exclusion

```terraform
resource "cortex_exclusion_list" "internal_hosts" {
  value  = "^host-[0-9]+\\.internal\\.corp$"
  type   = "regex"
  reason = "Internal hostname pattern"
}
```

### Multiple Exclusions

```terraform
locals {
  internal_cidrs = {
    rfc1918_10  = "10.0.0.0/8"
    rfc1918_172 = "172.16.0.0/12"
    rfc1918_192 = "192.168.0.0/16"
  }
}

resource "cortex_exclusion_list" "rfc1918" {
  for_each = local.internal_cidrs

  value  = each.value
  type   = "CIDR"
  reason = "RFC 1918 private address range"
}
```

## Schema

### Required

- `value` (String, Forces Replacement) The indicator value to exclude. Can be an IP address, CIDR range, domain, or regex pattern depending on the `type`.
- `type` (String, Forces Replacement) The type of exclusion entry. Valid values are `standard`, `CIDR`, or `regex`.

### Optional

- `reason` (String) A human-readable reason for the exclusion.

### Read-Only

- `id` (String) The identifier of the exclusion list entry. Same as `value`.
- `version` (Number) The current version of the exclusion list entry. Incremented on each update by the server.

## Import

Exclusion list entries can be imported using the indicator value:

```shell
terraform import cortex_exclusion_list.internal_network "10.0.0.0/8"
```
