---
page_title: "cortex_parsing_rules Resource - cortex"
subcategory: ""
description: |-
  Manages XQL parsing rules in XSIAM.
---

# cortex_parsing_rules (Resource)

Manages the singleton XQL parsing rules configuration in XSIAM. Parsing rules define how raw log data is parsed and transformed into structured fields before ingestion into the data lake.

This is a singleton resource -- only one `cortex_parsing_rules` resource should exist per XSIAM tenant. The resource manages the full text of all parsing rules as a single block of XQL. Updates use hash-based optimistic locking to prevent concurrent modification conflicts. Destroying this resource clears the parsing rules text.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

~> **Important:** This resource manages ALL parsing rules as a single text block. Any parsing rules created outside of Terraform will be overwritten on the next apply.

## Example Usage

```terraform
resource "cortex_parsing_rules" "config" {
  text = <<-XQL
    [RULE: syslog_parsing]
    alter
        _raw_log = to_string(rawlog),
        facility = arrayindex(split(_raw_log, "|"), 0),
        severity = arrayindex(split(_raw_log, "|"), 1),
        message  = arrayindex(split(_raw_log, "|"), 2)
    | filter severity != null;

    [RULE: json_log_parsing]
    alter
        parsed = json_extract_scalar(rawlog, "$.message"),
        src_ip = json_extract_scalar(rawlog, "$.source_ip"),
        action = json_extract_scalar(rawlog, "$.action")
    | filter parsed != null;
  XQL
}
```

### Minimal Configuration

```terraform
resource "cortex_parsing_rules" "config" {
  text = "[RULE: placeholder]\nalter _raw_log = to_string(rawlog);"
}
```

## Argument Reference

* `text` - (Required) The full XQL parsing rules text. This replaces all existing parsing rules in XSIAM. Use heredoc syntax (`<<-XQL ... XQL`) for multi-rule configurations.

## Attributes Reference

* `hash` - The hash of the current parsing rules text. Used internally for optimistic locking to detect concurrent modifications.

## Import

The parsing rules are a singleton and can be imported using the literal string `parsing_rules`:

```shell
terraform import cortex_parsing_rules.config parsing_rules
```
