---
page_title: "cortex_security_settings Resource - terraform-provider-cortex"
subcategory: ""
description: |-
  Manages the security settings in Cortex XSOAR 8 OPP. This singleton resource controls login policies, session timeouts, IP restrictions, and other security configurations.
---

# cortex_security_settings (Resource)

Manages the security settings in Cortex XSOAR 8 OPP (On-Premise Private). This is a singleton resource that controls various security policies including login expiration, session timeouts, IP access restrictions, domain allowlists, and user inactivity settings.

Supported on XSOAR 8 OPP only. Requires session authentication (provider `ui_url`, `username`, and `password` must be configured).

~> **Note:** This is a singleton resource. Only one `cortex_security_settings` resource should exist in your Terraform configuration. The resource manages settings that are global to the XSOAR instance.

~> **Note:** This resource requires session-based authentication to the XSOAR 8 OPP webapp API. Ensure the provider is configured with `ui_url`, `username`, and `password` in addition to the standard `api_url` and `api_key`.

## Example Usage

### Basic Security Hardening

```terraform
resource "cortex_security_settings" "this" {
  user_login_expiration = 30
  auto_logout_enabled   = true
  auto_logout_time      = 15
  dashboard_expiration  = 1440
}
```

### IP and Domain Restrictions

```terraform
resource "cortex_security_settings" "this" {
  user_login_expiration = 60
  auto_logout_enabled   = true
  auto_logout_time      = 30
  dashboard_expiration  = 10080

  approved_ip_ranges = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.1.0/24",
  ]

  approved_domains = [
    "corp.example.com",
    "secure.example.com",
  ]

  approved_mailing_domains = [
    "example.com",
  ]

  limit_api_access = true
}
```

### Full Configuration with Inactive User Management

```terraform
resource "cortex_security_settings" "this" {
  # Login and session
  user_login_expiration = 90
  auto_logout_enabled   = true
  auto_logout_time      = 20
  dashboard_expiration  = 4320

  # IP restrictions
  approved_ip_ranges = [
    "10.0.0.0/8",
  ]
  limit_api_access = true

  # Domain restrictions
  approved_domains = [
    "xsoar.internal.corp",
  ]

  approved_mailing_domains = [
    "corp.example.com",
  ]

  # User inactivity
  inactive_users_is_enable = true
  time_to_inactive_users   = 21600

  # Monitoring
  external_ip_monitoring = true
}
```

## Schema

### Optional

- `user_login_expiration` (Number) The number of days before a user's login expires and they must re-authenticate. Defaults to `60`.
- `auto_logout_enabled` (Boolean) Whether automatic session logout on inactivity is enabled. Defaults to `false`.
- `auto_logout_time` (Number) The number of minutes of inactivity before a user is automatically logged out. Only effective when `auto_logout_enabled` is `true`. Defaults to `30`.
- `dashboard_expiration` (Number) The number of minutes before dashboard sessions expire. Defaults to `10080` (7 days).
- `approved_ip_ranges` (List of String) A list of IP addresses or CIDR ranges that are allowed to access the XSOAR instance. When set, access from IPs not in this list is denied.
- `approved_domains` (List of String) A list of approved domains for accessing the XSOAR instance.
- `time_to_inactive_users` (Number) The number of minutes after which a user account is marked as inactive. Defaults to `43200` (30 days).
- `inactive_users_is_enable` (Boolean) Whether automatic user inactivity detection is enabled. Defaults to `false`.
- `approved_mailing_domains` (List of String) A list of approved email domains for user notifications and reports.
- `external_ip_monitoring` (Boolean) Whether monitoring of external IP access is enabled. Defaults to `true`.
- `limit_api_access` (Boolean) Whether API access is restricted to the `approved_ip_ranges`. Defaults to `false`.

### Read-Only

- `id` (String) The identifier of the security settings resource.

## Import

Import is not supported for this resource. To bring existing security settings under Terraform management, define the resource in your configuration and run `terraform apply`. Terraform will read the current settings and update them to match your configuration.
