---
page_title: "cortex_data_modeling_rules Resource - cortex"
subcategory: ""
description: |-
  Manages XQL data modeling rules in XSIAM.
---

# cortex_data_modeling_rules (Resource)

Manages the singleton XQL data modeling rules configuration in XSIAM. Data modeling rules define how parsed log data is mapped to the Cortex Data Model (CDM) schema, normalizing fields across different log sources into a unified structure for correlation and analytics.

This is a singleton resource -- only one `cortex_data_modeling_rules` resource should exist per XSIAM tenant. The resource manages the full text of all data modeling rules as a single block of XQL. Updates use hash-based optimistic locking to prevent concurrent modification conflicts. Destroying this resource clears the data modeling rules text.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

~> **Important:** This resource manages ALL data modeling rules as a single text block. Any data modeling rules created outside of Terraform will be overwritten on the next apply.

## Example Usage

```terraform
resource "cortex_data_modeling_rules" "config" {
  text = <<-XQL
    [MODEL: firewall_traffic_model]
    alter
        xdm.source.ipv4      = src_ip,
        xdm.target.ipv4      = dst_ip,
        xdm.source.port      = to_integer(src_port),
        xdm.target.port      = to_integer(dst_port),
        xdm.network.protocol = protocol,
        xdm.observer.action  = action
    | filter src_ip != null;

    [MODEL: authentication_model]
    alter
        xdm.source.user.username = username,
        xdm.event.outcome        = if(status = "success", XDM_CONST.OUTCOME_SUCCESS, XDM_CONST.OUTCOME_FAILURE),
        xdm.source.ipv4          = client_ip,
        xdm.event.type            = "AUTH"
    | filter username != null;
  XQL
}
```

### Minimal Configuration

```terraform
resource "cortex_data_modeling_rules" "config" {
  text = "[MODEL: placeholder]\nalter xdm.event.type = \"GENERIC\";"
}
```

## Argument Reference

* `text` - (Required) The full XQL data modeling rules text. This replaces all existing data modeling rules in XSIAM. Use heredoc syntax (`<<-XQL ... XQL`) for multi-rule configurations.

## Attributes Reference

* `hash` - The hash of the current data modeling rules text. Used internally for optimistic locking to detect concurrent modifications.
* `last_update` - The timestamp of the last update to the data modeling rules, as reported by XSIAM.

## Import

The data modeling rules are a singleton and can be imported using the literal string `data_modeling_rules`:

```shell
terraform import cortex_data_modeling_rules.config data_modeling_rules
```
