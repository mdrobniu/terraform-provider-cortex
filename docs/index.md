---
page_title: "Provider: Cortex"
description: |-
  The Cortex provider manages Palo Alto Cortex XSOAR and XSIAM instance configuration via Terraform.
---

# Cortex Provider

The Cortex provider enables Terraform to manage [Palo Alto Cortex XSOAR](https://www.paloaltonetworks.com/cortex/xsoar) and [Cortex XSIAM](https://www.paloaltonetworks.com/cortex/cortex-xsiam) instance configuration as infrastructure-as-code. It supports XSOAR 6, XSOAR 8 On-Prem/Private (OPP), XSOAR 8 SaaS, and XSIAM deployments.

The provider automatically detects the product version and deployment mode via the `/about` endpoint and selects the appropriate API backend.

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

### XSIAM

```terraform
provider "cortex" {
  base_url = "https://api-xsiam.xdr.us.paloaltonetworks.com"
  api_key  = var.xsiam_api_key
  auth_id  = var.xsiam_auth_id
  insecure = true
}
```

### XSIAM / XSOAR 8 SaaS with Session Token

Required for webapp-only resources (correlation rules, datasets, etc.) on XSIAM and XSOAR 8 SaaS.

```terraform
provider "cortex" {
  base_url      = "https://api-xsiam.xdr.us.paloaltonetworks.com"
  api_key       = var.xsiam_api_key
  auth_id       = var.xsiam_auth_id
  insecure      = true
  session_token = var.session_token
}
```

## Authentication

All arguments can also be set via environment variables. Environment variables take lower precedence than provider configuration.

| Argument        | Environment Variable       | Description                                  |
|-----------------|----------------------------|----------------------------------------------|
| `base_url`      | `DEMISTO_BASE_URL`         | API base URL                                 |
| `api_key`       | `DEMISTO_API_KEY`          | API key for authentication                   |
| `auth_id`       | `DEMISTO_AUTH_ID`          | Auth ID for XSOAR 8 / XSIAM                 |
| `insecure`      | `DEMISTO_INSECURE`         | Skip TLS certificate verification            |
| `ui_url`        | `XSOAR_UI_URL`             | UI URL for OPP session auth                  |
| `username`      | `XSOAR_USERNAME`           | Username for OPP session auth                |
| `password`      | `XSOAR_PASSWORD`           | Password for OPP session auth                |
| `session_token` | `CORTEX_SESSION_TOKEN`     | Session token for XSIAM/SaaS webapp auth     |

### Authentication by Deployment

| Deployment   | Auth Method                                                         |
|--------------|---------------------------------------------------------------------|
| XSOAR 6      | `api_key` only                                                      |
| XSOAR 8 OPP  | `api_key` + `auth_id`; optionally `ui_url` + `username` + `password` for webapp resources |
| XSOAR 8 SaaS | `api_key` + `auth_id`; optionally `session_token` for webapp resources |
| XSIAM        | `api_key` + `auth_id`; optionally `session_token` for webapp resources |

## Schema

### Optional

- `base_url` (String) The base URL of the XSOAR/XSIAM instance API. For XSOAR 6, this is the instance URL (e.g., `https://xsoar.example.com`). For XSOAR 8 and XSIAM, use the API URL (e.g., `https://api-xsoar8.example.com`). Can also be set via `DEMISTO_BASE_URL` environment variable.
- `api_key` (String, Sensitive) API key for authentication. Can also be set via `DEMISTO_API_KEY` environment variable.
- `auth_id` (String) Authentication ID for XSOAR 8 and XSIAM (`x-xdr-auth-id` header). Can also be set via `DEMISTO_AUTH_ID` environment variable. Not needed for XSOAR 6.
- `insecure` (Boolean) Skip TLS certificate verification. Can also be set via `DEMISTO_INSECURE` environment variable.
- `ui_url` (String) The UI URL for XSOAR 8 OPP session auth. Required for managing external storage, backup schedules, and security settings on OPP. Can also be set via `XSOAR_UI_URL` environment variable.
- `username` (String) Username for XSOAR 8 OPP session auth. Can also be set via `XSOAR_USERNAME` environment variable.
- `password` (String, Sensitive) Password for XSOAR 8 OPP session auth. Can also be set via `XSOAR_PASSWORD` environment variable.
- `session_token` (String, Sensitive) Session token for webapp API access on XSIAM and XSOAR 8 SaaS. Obtain by logging into the UI, then copying the session cookie value from browser DevTools. Required for correlation rules, datasets, and other webapp-managed resources. Can also be set via `CORTEX_SESSION_TOKEN` environment variable.
