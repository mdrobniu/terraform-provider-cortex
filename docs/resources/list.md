---
page_title: "cortex_list Resource - cortex"
subcategory: ""
description: |-
  Manages a list in Cortex XSOAR/XSIAM. Lists store configuration data such as IP lists, CSV tables, or JSON config used by playbooks and integrations.
---

# cortex_list (Resource)

Manages a list in Cortex XSOAR/XSIAM. Lists store configuration data such as IP allow/deny lists, CSV lookup tables, JSON configuration, or any text-based data used by playbooks and integrations.

Supported on XSOAR 6, XSOAR 8 OPP, XSOAR 8 SaaS, and XSIAM.

~> **Note:** Changing the `name` attribute forces replacement of the resource (destroy and recreate). The list name is used as the unique identifier.

## Example Usage

### Plain Text List

```terraform
resource "cortex_list" "allowed_ips" {
  name = "AllowedIPs"
  type = "plain_text"
  data = <<-EOT
    10.0.0.1
    10.0.0.2
    10.0.0.3
    192.168.1.0/24
  EOT
}
```

### JSON Configuration List

```terraform
resource "cortex_list" "config" {
  name = "AppConfig"
  type = "json"
  data = jsonencode({
    max_retries      = 3
    timeout_seconds  = 30
    allowed_domains  = ["example.com", "corp.internal"]
    notifications    = true
  })
}
```

### Markdown Documentation List

```terraform
resource "cortex_list" "runbook" {
  name = "IncidentRunbook"
  type = "markdown"
  data = <<-EOT
    # Incident Response Runbook

    ## Step 1: Triage
    - Review alert details
    - Determine severity

    ## Step 2: Containment
    - Isolate affected hosts
    - Block malicious IPs
  EOT
}
```

### CSV Lookup Table

```terraform
resource "cortex_list" "ip_lookup" {
  name = "IPToLocationLookup"
  type = "plain_text"
  data = <<-EOT
    ip,location,owner
    10.0.1.0/24,US-East,Engineering
    10.0.2.0/24,US-West,Operations
    10.0.3.0/24,EU-West,Security
  EOT
}
```

### Multiple Lists with for_each

```terraform
locals {
  lists = {
    "AllowedDomains" = {
      type = "plain_text"
      data = "example.com\ncorp.internal\npartner.net"
    }
    "BlockedIPs" = {
      type = "plain_text"
      data = "192.0.2.1\n198.51.100.0/24"
    }
  }
}

resource "cortex_list" "managed" {
  for_each = local.lists

  name = each.key
  type = each.value.type
  data = each.value.data
}
```

## Schema

### Required

- `name` (String, Forces Replacement) The name of the list. Also serves as the list identifier. Changing this value forces the resource to be destroyed and recreated.
- `data` (String) The content of the list as a string. For JSON lists, use `jsonencode()`. For multi-line text, use heredoc syntax (`<<-EOT`).

### Optional

- `type` (String) The content type of the list. Valid values: `plain_text` (default), `json`, `html`, `markdown`, `css`.

### Read-Only

- `id` (String) The unique identifier of the list. Same as `name`.
- `version` (Number) The current version of the list. Incremented on each update by the server.

## Import

Lists can be imported using the list name:

```shell
terraform import cortex_list.allowed_ips AllowedIPs
```
