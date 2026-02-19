---
page_title: "cortex_preprocessing_rule Resource - cortex"
subcategory: ""
description: |-
  Manages a preprocessing rule in XSOAR.
---

# cortex_preprocessing_rule (Resource)

Manages a preprocessing rule in XSOAR.

Preprocessing rules evaluate incoming incidents before they are created, allowing you to drop, modify, or link them based on conditions. Rules are evaluated in order and can execute scripts or link incidents to existing ones.

~> **Note (XSOAR 8 SaaS):** This resource is **not available** on XSOAR 8 SaaS deployments.

## Example Usage

### Drop duplicate incidents

```terraform
resource "cortex_preprocessing_rule" "drop_duplicates" {
  name    = "Drop Duplicate Alerts"
  enabled = true
  action  = "drop"

  rules_json = jsonencode([
    {
      name     = "name"
      operator = "isEqualString"
      value    = "Duplicate Alert"
    }
  ])
}
```

### Run a script on matching incidents

```terraform
resource "cortex_preprocessing_rule" "enrich" {
  name        = "Enrich Phishing"
  enabled     = true
  action      = "run_script"
  script_name = "PhishingPreprocess"

  rules_json = jsonencode([
    {
      name     = "type"
      operator = "isEqualString"
      value    = "Phishing"
    }
  ])
}
```

### Link incidents to existing ones

```terraform
resource "cortex_preprocessing_rule" "link_incidents" {
  name    = "Link Related Alerts"
  enabled = true
  action  = "link"

  rules_json = jsonencode([
    {
      name     = "severity"
      operator = "isEqualNumber"
      value    = "4"
    }
  ])
}
```

## Schema

### Required

- `name` (String) The display name of the preprocessing rule.
- `action` (String) The action to take when the rule matches. Valid values are `"drop"`, `"run_script"`, and `"link"`.
- `rules_json` (String) A JSON-encoded array of filter conditions that determine when the rule applies. Each condition specifies a field name, operator, and value.

### Optional

- `enabled` (Boolean) Whether the preprocessing rule is active. Defaults to `true`.
- `script_name` (String) The name of the script to execute when `action` is `"run_script"`.

### Read-Only

- `id` (String) The unique identifier of the preprocessing rule.
- `version` (Number) The internal version of the rule, used for optimistic locking.

## Import

Import is supported using the rule ID:

```shell
terraform import cortex_preprocessing_rule.drop_duplicates "Drop Duplicate Alerts"
```
