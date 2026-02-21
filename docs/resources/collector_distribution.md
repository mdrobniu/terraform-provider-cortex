---
page_title: "cortex_collector_distribution Resource - cortex"
subcategory: ""
description: |-
  Manages XDR collector distribution packages in XSIAM.
---

# cortex_collector_distribution (Resource)

Manages XDR collector distribution packages in XSIAM. Distribution packages are pre-configured installer bundles for deploying data collection agents to endpoints. Each distribution targets a specific platform and agent version combination.

This resource does not support in-place updates. Any change to the distribution configuration will trigger a delete and recreate cycle, since the XSIAM API does not provide an update endpoint for collector distributions.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

~> **Important:** All mutable attributes force resource replacement. Changing any attribute will destroy the existing distribution and create a new one.

## Example Usage

### Windows Distribution

```terraform
resource "cortex_collector_distribution" "windows_prod" {
  name          = "Production Windows Collector"
  description   = "Standard collector package for Windows production servers"
  agent_version = "8.3.0"
  platform      = "AGENT_OS_WINDOWS"
}
```

### Linux Distribution

```terraform
resource "cortex_collector_distribution" "linux_prod" {
  name          = "Production Linux Collector"
  description   = "Standard collector package for Linux production servers"
  agent_version = "8.3.0"
  platform      = "AGENT_OS_LINUX"
  package_type  = "SCOUTER_INSTALLER"
}
```

## Argument Reference

* `name` - (Required, Forces new resource) The display name of the distribution package.
* `agent_version` - (Required, Forces new resource) The version of the collector agent included in the distribution (e.g., `"8.3.0"`).
* `platform` - (Required, Forces new resource) The target operating system platform. Valid values are `AGENT_OS_WINDOWS` or `AGENT_OS_LINUX`.
* `description` - (Optional, Forces new resource) A description of the distribution package.
* `package_type` - (Optional, Forces new resource) The type of installer package. Defaults to `SCOUTER_INSTALLER` if not specified.

## Attributes Reference

* `distribution_id` - The UUID assigned to the distribution package by XSIAM.
* `created_by` - The user who created the distribution package.

## Import

Collector distributions can be imported using their distribution ID (UUID):

```shell
terraform import cortex_collector_distribution.windows_prod a1b2c3d4-e5f6-7890-abcd-ef1234567890
```
