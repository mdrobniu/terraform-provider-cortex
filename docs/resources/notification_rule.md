---
page_title: "cortex_notification_rule Resource - cortex"
subcategory: ""
description: |-
  Manages notification rules in XSIAM.
---

# cortex_notification_rule (Resource)

Manages notification rules in XSIAM. Notification rules define how and when alerts or audit events are forwarded to external destinations such as email recipients or syslog servers.

Rules can filter which events trigger notifications and control delivery settings such as email aggregation intervals and syslog forwarding.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

### Alert Email Notification

```terraform
resource "cortex_notification_rule" "critical_alerts" {
  name         = "Critical Alert Notifications"
  description  = "Email SOC team on critical alerts"
  forward_type = "Alert"
  enabled      = true

  email_distribution_list = [
    "soc-team@example.com",
    "security-leads@example.com"
  ]

  email_aggregation = 300

  filter = jsonencode({
    field    = "severity"
    operator = "gte"
    value    = "critical"
  })
}
```

### Audit Syslog Forwarding

```terraform
resource "cortex_notification_rule" "audit_syslog" {
  name           = "Audit Log Forwarding"
  description    = "Forward all audit events to SIEM"
  forward_type   = "Audit"
  enabled        = true
  syslog_enabled = true
}
```

### Combined Email and Syslog

```terraform
resource "cortex_notification_rule" "high_severity" {
  name         = "High Severity Alerts"
  description  = "Forward high severity alerts via email and syslog"
  forward_type = "Alert"
  enabled      = true

  email_distribution_list = ["oncall@example.com"]
  email_aggregation       = 60
  syslog_enabled          = true

  filter = jsonencode({
    field    = "severity"
    operator = "in"
    value    = ["high", "critical"]
  })
}
```

## Argument Reference

* `name` - (Required) The display name of the notification rule.
* `description` - (Optional) A description of the notification rule's purpose.
* `forward_type` - (Required) The type of events to forward. Valid values are `Alert` (security alerts) or `Audit` (audit log events).
* `filter` - (Optional) A JSON-encoded filter expression that determines which events trigger the notification. If omitted, all events of the specified `forward_type` will be forwarded.
* `email_distribution_list` - (Optional) A list of email addresses to receive notifications.
* `email_aggregation` - (Optional) The aggregation interval in seconds for email notifications. Multiple events within this interval are combined into a single email. Set to `0` for immediate delivery.
* `syslog_enabled` - (Optional) Whether to forward matching events to the configured syslog server. Defaults to `false`.
* `enabled` - (Optional) Whether the notification rule is active. Defaults to `true`.

## Attributes Reference

* `rule_id` - The unique identifier assigned to the notification rule by XSIAM.

## Import

Notification rules can be imported using their rule ID:

```shell
terraform import cortex_notification_rule.critical_alerts 12345
```
