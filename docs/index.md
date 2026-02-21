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
  base_url = "https://api-mytenant.xdr.us.paloaltonetworks.com"
  api_key  = var.xsiam_api_key
  auth_id  = var.xsiam_auth_id
  insecure = true
}
```

### XSIAM / XSOAR 8 SaaS with Session Token

Required for XSIAM webapp-only resources. The session token enables access to 23 XSIAM-specific resources and 3 data sources:

**Detection & Response:**
- `cortex_correlation_rule`, `cortex_ioc_rule` - Detection rules
- `cortex_bioc_rule` - Behavioral Indicator of Compromise rules
- `cortex_tim_rule` - Threat Intelligence Management rules
- `cortex_analytics_detector` - Analytics detection rule overrides
- `cortex_attack_surface_rule` - Attack surface rule overrides
- `cortex_rules_exception` - Detection rule exceptions

**Endpoint & Collector Management:**
- `cortex_agent_group` - Endpoint agent groups
- `cortex_collector_group` - XDR collector groups
- `cortex_collector_distribution` - XDR collector distribution packages
- `cortex_collector_profile` - XDR collector profiles
- `cortex_auto_upgrade_settings` - Collector auto-upgrade settings

**Configuration & Content:**
- `cortex_edl` - External Dynamic List configuration
- `cortex_vulnerability_scan_settings` - Vulnerability scan engine settings
- `cortex_parsing_rules` - XQL parsing rules
- `cortex_data_modeling_rules` - XQL data modeling rules
- `cortex_notification_rule` - Alert notification/forwarding rules
- `cortex_fim_rule_group`, `cortex_fim_rule` - File Integrity Monitoring
- `cortex_device_control_class` - USB device control classes
- `cortex_custom_status` - Custom alert/incident statuses
- `cortex_incident_domain` - Incident domain categories
- `cortex_asm_asset_removal` - Bulk ASM asset removal

**Data Sources:**
- `data.cortex_datasets` - List all XSIAM datasets
- `data.cortex_broker_vms` - List broker VM devices
- `data.cortex_collector_policies` - List collector policies

> **Note:** XSIAM webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

```terraform
provider "cortex" {
  base_url      = "https://api-mytenant.xdr.us.paloaltonetworks.com"
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
| XSIAM        | `api_key` + `auth_id`; optionally `session_token` for 23 XSIAM webapp resources + 3 data sources |

## Schema

### Optional

- `base_url` (String) The base URL of the XSOAR/XSIAM instance API. For XSOAR 6, this is the instance URL (e.g., `https://xsoar.example.com`). For XSOAR 8 and XSIAM, use the API URL (e.g., `https://api-xsoar8.example.com`). Can also be set via `DEMISTO_BASE_URL` environment variable.
- `api_key` (String, Sensitive) API key for authentication. Can also be set via `DEMISTO_API_KEY` environment variable.
- `auth_id` (String) Authentication ID for XSOAR 8 and XSIAM (`x-xdr-auth-id` header). Can also be set via `DEMISTO_AUTH_ID` environment variable. Not needed for XSOAR 6.
- `insecure` (Boolean) Skip TLS certificate verification. Can also be set via `DEMISTO_INSECURE` environment variable.
- `ui_url` (String) The UI URL for XSOAR 8 OPP session auth. Required for managing external storage, backup schedules, and security settings on OPP. Can also be set via `XSOAR_UI_URL` environment variable.
- `username` (String) Username for XSOAR 8 OPP session auth. Can also be set via `XSOAR_USERNAME` environment variable.
- `password` (String, Sensitive) Password for XSOAR 8 OPP session auth. Can also be set via `XSOAR_PASSWORD` environment variable.
- `session_token` (String, Sensitive) Session token for webapp API access on XSIAM and XSOAR 8 SaaS. Obtain by logging into the UI, then copying the session cookie value from browser DevTools. Required for correlation rules, IOC rules, EDL, vulnerability scan settings, agent groups, notification rules, BIOC rules, TIM rules, FIM rules, analytics detectors, attack surface rules, device control classes, custom statuses, incident domains, and rules exceptions. Can also be set via `CORTEX_SESSION_TOKEN` environment variable.

## Obtaining a Session Token

XSIAM and XSOAR 8 SaaS use SSO authentication for their web UI. The 23 webapp-only resources and 3 data sources listed above require a session token that represents an authenticated browser session. There are three ways to obtain this token:

### Method 1: cortex-login CLI Tool (Recommended)

The `cortex-login` tool included in `tools/cortex-login/` automates browser-based SSO login and captures session cookies:

```bash
pip install playwright
playwright install chromium

# Interactive login (opens browser for SSO)
cortex-login --url https://mytenant.xdr.us.paloaltonetworks.com

# Headless mode (paste cookies from browser DevTools)
cortex-login --headless

# Check session status
cortex-login --status
```

The tool saves the session to `~/.cortex/session.json`. The provider automatically loads this file when no `session_token` is configured, providing seamless authentication without manual token management.

### Method 2: Browser DevTools

1. Log into the XSIAM or XSOAR 8 SaaS web UI
2. Open browser DevTools (F12) -> Application -> Cookies
3. Copy the value of the session cookie (typically named `app-proxy-hydra-prod-us` or similar)
4. Set it as the `session_token` provider argument or `CORTEX_SESSION_TOKEN` environment variable

### Method 3: Session File

If you have session cookies from another tool or process, create `~/.cortex/session.json` with this format:

```json
{
  "url": "https://mytenant.xdr.us.paloaltonetworks.com",
  "cookies": {
    "app-proxy-hydra-prod-us": "YOUR_COOKIE_VALUE"
  }
}
```

The provider automatically detects and uses this file.

-> **Note:** Session tokens expire (typically after 8 hours). Re-run `cortex-login` or obtain a fresh token when the session expires.

## Webapp API Version Compatibility

The 23 XSIAM webapp resources and 3 data sources use internal webapp API endpoints that are **not part of the official public API**. These endpoints were reverse-engineered from the XSIAM web UI and are subject to change between XSIAM versions.

**This provider was developed and tested against Cortex XSIAM V3.4.** Webapp API endpoints may differ on other XSIAM or XSOAR 8 SaaS versions. If you encounter errors with webapp resources on a different version, the underlying API endpoints may have changed.

The provider uses two distinct API surfaces:

| API Surface | Auth Method | Resources | Stability |
|-------------|-------------|-----------|-----------|
| **Public API** (`/xsoar/...`, `/public_api/...`) | API key + auth-id | credential, job, exclusion_list, list, password_policy, server_config, marketplace_pack, etc. | Stable, officially documented |
| **Webapp API** (`/api/webapp/...`) | Session token (cookies) | correlation_rule, ioc_rule, edl, vulnerability_scan_settings, agent_group, notification_rule, bioc_rule, tim_rule, fim_rule, analytics_detector, attack_surface_rule, device_control_class, custom_status, incident_domain, rules_exception, parsing_rules, data_modeling_rules, auto_upgrade_settings, collector_group, collector_distribution, collector_profile, asm_asset_removal, + 3 data sources | Version-specific, may change |

If a webapp resource stops working after an XSIAM upgrade, enable debug logging (`TF_LOG=TRACE`) to inspect the API request/response and identify endpoint changes.
