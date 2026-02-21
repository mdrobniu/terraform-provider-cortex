---
page_title: "cortex_tim_rule Resource - cortex"
subcategory: ""
description: |-
  Manages Threat Intelligence Management (TIM) rules in XSIAM.
---

# cortex_tim_rule (Resource)

Manages Threat Intelligence Management (TIM) rules in XSIAM. TIM rules define automated actions to take on threat indicators based on matching criteria, such as enrichment, tagging, or expiration.

Rules are created in a disabled state by default and must be explicitly enabled via the `status` argument.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

```terraform
resource "cortex_tim_rule" "block_malicious_ips" {
  name        = "Block Malicious IPs"
  type        = "enrichment"
  severity    = "high"
  status      = "ENABLED"
  description = "Automatically enrich and tag malicious IP indicators"

  target = jsonencode({
    indicator_type = "IP"
    feed_names     = ["AlienVault OTX", "Abuse.ch"]
  })
}

resource "cortex_tim_rule" "expire_stale_indicators" {
  name        = "Expire Stale Indicators"
  type        = "expiration"
  severity    = "low"
  description = "Remove indicators older than 90 days"
}
```

## Argument Reference

* `name` - (Required) The display name of the TIM rule.
* `type` - (Required) The type of TIM rule (e.g., `enrichment`, `expiration`, `tagging`).
* `severity` - (Required) The severity level of the rule (e.g., `low`, `medium`, `high`, `critical`).
* `status` - (Optional) The operational status of the rule. Valid values are `ENABLED` or `DISABLED`. Defaults to `DISABLED`.
* `description` - (Optional) A description of the TIM rule's purpose.
* `target` - (Optional) A JSON-encoded object defining the target criteria for the rule, such as indicator types and feed sources.

## Attributes Reference

* `rule_id` - The unique identifier assigned to the TIM rule by XSIAM.

## Import

TIM rules can be imported using their rule ID:

```shell
terraform import cortex_tim_rule.block_malicious_ips 12345
```
