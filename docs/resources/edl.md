---
page_title: "cortex_edl Resource - cortex"
subcategory: ""
description: |-
  Manages the External Dynamic List (EDL) configuration in XSIAM.
---

# cortex_edl (Resource)

Manages the singleton External Dynamic List (EDL) configuration in XSIAM. EDL exposes threat intelligence indicators as external feeds that can be consumed by firewalls and other security devices.

This is a singleton resource -- only one `cortex_edl` resource should exist per XSIAM tenant. It configures the global EDL service settings including authentication credentials. The EDL service URLs for IP and domain feeds are computed by XSIAM and exposed as read-only attributes.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

```terraform
resource "cortex_edl" "config" {
  enabled  = true
  username = "edl-consumer"
  password = "s3cure-p@ssw0rd"
}

# Use the computed URLs in other resources or outputs
output "edl_ip_url" {
  value     = cortex_edl.config.url_ip
  sensitive = true
}

output "edl_domain_url" {
  value     = cortex_edl.config.url_domain
  sensitive = true
}
```

## Argument Reference

* `enabled` - (Required) Whether the EDL service is enabled. Set to `true` to activate the EDL feeds.
* `username` - (Required) The username for authenticating to the EDL feed endpoints.
* `password` - (Required, Sensitive) The password for authenticating to the EDL feed endpoints.

## Attributes Reference

* `url_ip` - The URL for the IP indicators EDL feed. Computed by XSIAM.
* `url_domain` - The URL for the domain indicators EDL feed. Computed by XSIAM.

## Import

The EDL configuration is a singleton and can be imported using the literal string `edl`:

```shell
terraform import cortex_edl.config edl
```
