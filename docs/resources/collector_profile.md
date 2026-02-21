---
page_title: "cortex_collector_profile Resource - cortex"
subcategory: ""
description: |-
  Manages XDR collector profiles in XSIAM.
---

# cortex_collector_profile (Resource)

Manages XDR collector profiles in XSIAM. Collector profiles define the configuration and module settings for data collection agents, controlling which data sources are collected and how the agent behaves on endpoints.

This is a create-only resource -- the XSIAM API does not provide update or delete endpoints for collector profiles. Any change to the profile configuration will trigger a recreate cycle (remove from state and create new). Destroying this resource removes it from Terraform state only; the profile remains in XSIAM.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

~> **Important:** There is no update or delete API for collector profiles. Terraform `destroy` only removes the profile from Terraform state -- it does not delete it from XSIAM. All attribute changes force resource replacement.

## Example Usage

```terraform
resource "cortex_collector_profile" "windows_standard" {
  name         = "Windows Standard Profile"
  description  = "Standard data collection profile for Windows endpoints"
  platform     = "AGENT_OS_WINDOWS"
  profile_type = "STANDARD"
  is_default   = false
  modules      = filebase64("${path.module}/profiles/windows_modules.yaml")
}
```

### Using Inline Base64 Encoding

```terraform
resource "cortex_collector_profile" "linux_minimal" {
  name        = "Linux Minimal Profile"
  description = "Minimal collection for Linux dev endpoints"
  platform    = "AGENT_OS_LINUX"
  modules     = base64encode(yamlencode({
    modules = {
      syslog = { enabled = true }
      audit  = { enabled = true }
      file   = { enabled = false }
    }
  }))
}
```

## Argument Reference

* `name` - (Required, Forces new resource) The display name of the collector profile.
* `platform` - (Required, Forces new resource) The target operating system platform. Valid values are `AGENT_OS_WINDOWS` or `AGENT_OS_LINUX`.
* `modules` - (Required, Forces new resource) The base64-encoded YAML modules configuration that defines which data collection modules are enabled and their settings.
* `description` - (Optional, Forces new resource) A description of the collector profile's purpose.
* `profile_type` - (Optional, Forces new resource) The type of collector profile. Defaults to `STANDARD` if not specified.
* `is_default` - (Optional) Whether this profile is the default for its platform. Defaults to `false`.

## Attributes Reference

* `profile_id` - The unique numeric identifier assigned to the collector profile by XSIAM.

## Import

Collector profiles can be imported using their profile ID:

```shell
terraform import cortex_collector_profile.windows_standard 12345
```

~> **Note:** After import, the `modules` attribute will contain the base64-encoded modules configuration as stored in XSIAM. Ensure your Terraform configuration matches to avoid unexpected replacement.
