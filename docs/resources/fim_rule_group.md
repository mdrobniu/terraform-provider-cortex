---
page_title: "cortex_fim_rule_group Resource - cortex"
subcategory: ""
description: |-
  Manages File Integrity Monitoring (FIM) rule groups in XSIAM.
---

# cortex_fim_rule_group (Resource)

Manages File Integrity Monitoring (FIM) rule groups in XSIAM. FIM rule groups are organizational containers for FIM rules that share a common operating system type and monitoring mode. Individual FIM rules (managed via `cortex_fim_rule`) are associated with a group.

The `os_type` is immutable after creation -- changing it requires destroying and recreating the group (and all associated rules).

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

```terraform
resource "cortex_fim_rule_group" "linux_config" {
  name            = "Linux Configuration Files"
  description     = "Monitor critical Linux configuration files"
  os_type         = "linux"
  monitoring_mode = "real_time"
}

resource "cortex_fim_rule_group" "windows_registry" {
  name            = "Windows Registry Keys"
  description     = "Monitor sensitive Windows registry entries"
  os_type         = "windows"
  monitoring_mode = "periodic"
}

# Associate rules with the group
resource "cortex_fim_rule" "etc_passwd" {
  type     = "FILE"
  path     = "/etc/passwd"
  group_id = cortex_fim_rule_group.linux_config.group_id
}
```

## Argument Reference

* `name` - (Required) The display name of the FIM rule group.
* `description` - (Optional) A description of the FIM rule group's purpose.
* `os_type` - (Required, Forces new resource) The operating system type for this rule group (e.g., `linux`, `windows`, `macos`). All rules in the group must target this OS. Changing this value will destroy and recreate the resource.
* `monitoring_mode` - (Required) The monitoring mode for the group. Valid values include `real_time` (immediate change detection) and `periodic` (scheduled scan intervals).

## Attributes Reference

* `group_id` - The unique identifier assigned to the FIM rule group by XSIAM.

## Import

FIM rule groups can be imported using their group ID:

```shell
terraform import cortex_fim_rule_group.linux_config 12345
```
