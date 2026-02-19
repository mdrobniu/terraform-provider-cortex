---
page_title: "Provider: Cortex"
description: |-
  The Cortex provider manages Palo Alto Cortex XSOAR instance configuration via Terraform.
---

# Cortex Provider

The Cortex provider enables Terraform to manage [Palo Alto Cortex XSOAR](https://www.paloaltonetworks.com/cortex/xsoar) instance configuration as infrastructure-as-code. It supports XSOAR 6, XSOAR 8 On-Prem/Private (OPP), and XSOAR 8 SaaS deployments.

The provider automatically detects the XSOAR version via the `/about` endpoint and selects the appropriate API backend.

> **DISCLAIMER:** This software is provided "as is" without warranty of any kind. Use at your own risk. See the [full disclaimer](https://github.com/mdrobniu/terraform-provider-cortex#disclaimer--limitation-of-liability) for details.

## Example Usage

### XSOAR 6

```terraform
provider "cortex" {
  base_url = "https://xsoar.example.com"
  api_key  = var.xsoar_api_key
  insecure = true
}
```

### XSOAR 8

```terraform
provider "cortex" {
  base_url = "https://api-xsoar8.example.com"
  api_key  = var.xsoar_api_key
  auth_id  = "9"
  insecure = true
}
```

### XSOAR 8 OPP with Session Auth

Required for `cortex_external_storage`, `cortex_backup_schedule`, and `cortex_security_settings` resources.

```terraform
provider "cortex" {
  base_url = "https://api-xsoar8.example.com"
  api_key  = var.xsoar_api_key
  auth_id  = "9"
  insecure = true

  ui_url   = "https://xsoar8.example.com"
  username = var.xsoar_username
  password = var.xsoar_password
}
```

## Authentication

All arguments can also be set via environment variables. Environment variables take lower precedence than provider configuration.

| Argument   | Environment Variable  | Description                              |
|------------|-----------------------|------------------------------------------|
| `base_url` | `DEMISTO_BASE_URL`    | XSOAR API base URL                       |
| `api_key`  | `DEMISTO_API_KEY`     | API key for authentication               |
| `auth_id`  | `DEMISTO_AUTH_ID`     | Auth ID for XSOAR 8                      |
| `insecure` | `DEMISTO_INSECURE`    | Skip TLS certificate verification        |
| `ui_url`   | `XSOAR_UI_URL`        | UI URL for OPP session auth              |
| `username` | `XSOAR_USERNAME`      | Username for OPP session auth            |
| `password` | `XSOAR_PASSWORD`      | Password for OPP session auth            |

## Schema

### Optional

- `base_url` (String) The base URL of the XSOAR instance (e.g., `https://xsoar.example.com`). Can also be set via `DEMISTO_BASE_URL` environment variable.
- `api_key` (String, Sensitive) API key for authentication. Can also be set via `DEMISTO_API_KEY` environment variable.
- `auth_id` (String) Authentication ID for XSOAR 8 (`x-xdr-auth-id` header). Can also be set via `DEMISTO_AUTH_ID` environment variable. Not needed for XSOAR 6.
- `insecure` (Boolean) Skip TLS certificate verification. Can also be set via `DEMISTO_INSECURE` environment variable.
- `ui_url` (String) The UI URL for XSOAR 8 OPP session auth. Required for managing external storage and backup schedules. Can also be set via `XSOAR_UI_URL` environment variable.
- `username` (String) Username for XSOAR 8 OPP session auth. Can also be set via `XSOAR_USERNAME` environment variable.
- `password` (String, Sensitive) Password for XSOAR 8 OPP session auth. Can also be set via `XSOAR_PASSWORD` environment variable.
