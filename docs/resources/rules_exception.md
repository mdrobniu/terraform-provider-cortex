---
page_title: "cortex_rules_exception Resource - cortex"
subcategory: ""
description: |-
  Manages rule exceptions in XSIAM.
---

# cortex_rules_exception (Resource)

Manages rule exceptions in XSIAM. Rule exceptions suppress specific alerts or detections that match defined criteria, reducing false positives without disabling the underlying detection rule entirely.

This resource does not support in-place updates. Any change to the exception configuration will trigger a delete and recreate cycle.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

~> **Important:** There is no update API for rule exceptions. Any attribute change will destroy and recreate the exception.

## Example Usage

```terraform
resource "cortex_rules_exception" "known_scanner" {
  name        = "Suppress Known Scanner Alerts"
  description = "Exclude alerts from authorized vulnerability scanner"

  filter = jsonencode({
    field    = "source_ip"
    operator = "in"
    value    = ["10.0.5.100", "10.0.5.101"]
  })
}

resource "cortex_rules_exception" "maintenance_window" {
  name        = "Maintenance Window Exception"
  description = "Suppress alerts during scheduled maintenance"
  alert_id    = "ALERT-12345"

  filter = jsonencode({
    field    = "host_name"
    operator = "eq"
    value    = "maintenance-server"
  })
}
```

## Argument Reference

* `name` - (Required) The display name of the rule exception.
* `description` - (Optional) A description of why this exception exists.
* `alert_id` - (Optional) The ID of a specific alert that triggered the need for this exception. Used for traceability.
* `filter` - (Optional) A JSON-encoded filter expression defining the criteria for suppressing alerts. Specifies which alerts should be excluded based on field values.

## Attributes Reference

* `rule_id` - The unique identifier assigned to the rule exception by XSIAM.
* `status` - The current status of the exception, as reported by XSIAM.

## Import

Rule exceptions can be imported using their rule ID:

```shell
terraform import cortex_rules_exception.known_scanner 12345
```
