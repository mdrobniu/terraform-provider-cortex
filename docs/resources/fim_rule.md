---
page_title: "cortex_fim_rule Resource - cortex"
subcategory: ""
description: |-
  Manages File Integrity Monitoring (FIM) rules in XSIAM.
---

# cortex_fim_rule (Resource)

Manages individual File Integrity Monitoring (FIM) rules in XSIAM. FIM rules define specific file paths or registry keys to monitor for unauthorized changes. Each rule must belong to a FIM rule group (managed via `cortex_fim_rule_group`).

The `type` is immutable after creation -- switching between FILE and REGISTRY requires destroying and recreating the rule.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

### File Monitoring (Linux)

```terraform
resource "cortex_fim_rule_group" "linux_config" {
  name            = "Linux Config"
  os_type         = "linux"
  monitoring_mode = "real_time"
}

resource "cortex_fim_rule" "etc_passwd" {
  type        = "FILE"
  path        = "/etc/passwd"
  description = "Monitor password file for unauthorized changes"
  group_id    = cortex_fim_rule_group.linux_config.group_id
}

resource "cortex_fim_rule" "ssh_config" {
  type               = "FILE"
  path               = "/etc/ssh/sshd_config"
  description        = "Monitor SSH daemon configuration"
  group_id           = cortex_fim_rule_group.linux_config.group_id
  monitor_all_events = true
}
```

### Registry Monitoring (Windows)

```terraform
resource "cortex_fim_rule_group" "windows_registry" {
  name            = "Windows Registry"
  os_type         = "windows"
  monitoring_mode = "real_time"
}

resource "cortex_fim_rule" "run_key" {
  type        = "REGISTRY"
  path        = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
  description = "Monitor autostart registry key"
  group_id    = cortex_fim_rule_group.windows_registry.group_id
}
```

## Argument Reference

* `type` - (Required, Forces new resource) The type of resource to monitor. Valid values are `FILE` (file system path) or `REGISTRY` (Windows registry key). Changing this value will destroy and recreate the resource.
* `path` - (Required) The file system path or registry key path to monitor.
* `description` - (Optional) A description of what this rule monitors and why.
* `group_id` - (Required) The ID of the FIM rule group this rule belongs to. Must reference an existing `cortex_fim_rule_group` resource.
* `monitor_all_events` - (Optional) Whether to monitor all file system events (create, modify, delete, rename) or only content modifications. Defaults to `false`.

## Attributes Reference

* `rule_id` - The unique identifier assigned to the FIM rule by XSIAM.

## Import

FIM rules can be imported using their rule ID:

```shell
terraform import cortex_fim_rule.etc_passwd 12345
```
