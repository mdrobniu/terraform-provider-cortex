---
page_title: "cortex_attack_surface_rule Resource - cortex"
subcategory: ""
description: |-
  Manages attack surface rule configurations in XSIAM.
---

# cortex_attack_surface_rule (Resource)

Manages attack surface rule configurations in XSIAM. Attack surface rules are system-defined rules that detect security issues in your external attack surface. Since these rules are predefined by XSIAM, this resource only allows modifying their `enabled_status` and `priority` -- it does not support creating or deleting rules.

The `issue_type_id` identifies the system-defined rule and is immutable. The `issue_type_name` and `description` are read-only attributes populated from the system definition.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

~> **Important:** This resource manages system-defined rules. Terraform `create` adopts the existing rule into state, and `destroy` removes it from state without deleting the rule from XSIAM.

## Example Usage

```terraform
resource "cortex_attack_surface_rule" "expired_cert" {
  issue_type_id  = "ExpiredCertificate"
  enabled_status = "ENABLED"
  priority       = "HIGH"
}

resource "cortex_attack_surface_rule" "open_port" {
  issue_type_id  = "OpenPort"
  enabled_status = "ENABLED"
  priority       = "MEDIUM"
}
```

## Argument Reference

* `issue_type_id` - (Required, Forces new resource) The unique identifier of the system-defined attack surface rule. Changing this value will destroy and recreate the resource (removing old rule from state and adopting the new one).
* `enabled_status` - (Required) Whether the rule is enabled. Valid values are `ENABLED` or `DISABLED`.
* `priority` - (Required) The priority level of the rule. Valid values include `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL`.

## Attributes Reference

* `issue_type_name` - The human-readable name of the attack surface rule, as defined by XSIAM.
* `description` - The system-provided description of what this rule detects.

## Import

Attack surface rules can be imported using their issue type ID:

```shell
terraform import cortex_attack_surface_rule.expired_cert ExpiredCertificate
```
