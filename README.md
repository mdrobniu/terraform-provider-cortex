# Terraform Provider for Cortex XSOAR / XSIAM

> **DISCLAIMER:** This software is provided "as is" without warranty of any kind.
> Use at your own risk. See [Disclaimer & Limitation of Liability](#disclaimer--limitation-of-liability) below.

A Terraform provider for managing [Palo Alto Cortex XSOAR](https://www.paloaltonetworks.com/cortex/xsoar) and [Cortex XSIAM](https://www.paloaltonetworks.com/cortex/cortex-xsiam) instance configuration as code. Supports XSOAR 6, XSOAR 8 On-Prem/Private (OPP), XSOAR 8 SaaS, and XSIAM deployments.

## Features

- **41 resources + 3 data sources** covering the full configuration surface
- **Multi-version support** -- automatically detects XSOAR 6, XSOAR 8, and XSIAM via the `/about` endpoint
- **Deployment-mode aware** -- handles XSOAR 8 OPP, SaaS, and XSIAM differences transparently
- **Session auth for OPP** -- optional webapp login for managing external storage, backup schedules, and security settings
- **Session token for XSIAM/SaaS** -- optional pre-obtained session token for webapp API access
- **Export tool** -- Python utility to export existing XSOAR configuration into `.tf` files
- **Drift detection** -- reads back state from the API after every apply to detect out-of-band changes

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/dl/) >= 1.22 (for building from source)
- A Cortex XSOAR (v6 or v8) or XSIAM instance with API key access

## Installation

### Build from source

```bash
git clone https://github.com/mdrobniu/terraform-provider-cortex.git
cd terraform-provider-cortex
make install
```

This builds the binary and copies it to `~/.terraform.d/plugins/registry.terraform.io/mdrobniu/cortex/0.1.0/linux_amd64/`.

## Quick Start

### 1. Configure the provider

```hcl
terraform {
  required_providers {
    cortex = {
      source  = "registry.terraform.io/mdrobniu/cortex"
      version = "~> 0.2"
    }
  }
}

# XSOAR 6
provider "cortex" {
  base_url = "https://xsoar.example.com"
  api_key  = var.xsoar_api_key
  insecure = true
}

# XSOAR 8 (requires auth_id)
provider "cortex" {
  base_url = "https://api-xsoar8.example.com"
  api_key  = var.xsoar_api_key
  auth_id  = "9"
  insecure = true
}

# XSIAM (requires auth_id)
provider "cortex" {
  base_url = "https://api-mytenant.xdr.us.paloaltonetworks.com"
  api_key  = var.xsiam_api_key
  auth_id  = var.xsiam_auth_id
  insecure = true
}
```

### Provider Arguments

All provider arguments can also be set via environment variables:

| Argument        | Environment Variable       | Description                                  |
|-----------------|----------------------------|----------------------------------------------|
| `base_url`      | `DEMISTO_BASE_URL`         | API base URL                                 |
| `api_key`       | `DEMISTO_API_KEY`          | API key for authentication                   |
| `auth_id`       | `DEMISTO_AUTH_ID`          | Auth ID header for XSOAR 8 / XSIAM          |
| `insecure`      | `DEMISTO_INSECURE`         | Skip TLS certificate verification            |
| `ui_url`        | `XSOAR_UI_URL`             | UI URL for XSOAR 8 OPP session auth          |
| `username`      | `XSOAR_USERNAME`           | Username for OPP session auth                |
| `password`      | `XSOAR_PASSWORD`           | Password for OPP session auth                |
| `session_token` | `CORTEX_SESSION_TOKEN`     | Session token for XSIAM/SaaS webapp auth     |

### 2. Create resources

```hcl
# Install a marketplace pack
resource "cortex_marketplace_pack" "common_scripts" {
  pack_id = "CommonScripts"
  version = "1.13.38"
}

# Create a scheduled job (XSOAR 6/8)
resource "cortex_job" "daily_cleanup" {
  name        = "Daily Incident Cleanup"
  playbook_id = "CloseStaleIncidents"
  scheduled   = true
  cron        = "0 2 * * *"
  recurrent   = true
}

# Create a scheduled job (XSIAM -- uses human_cron)
resource "cortex_job" "xsiam_feed" {
  name               = "Feed Ingestion"
  type               = "Unclassified"
  scheduled          = true
  recurrent          = true
  should_trigger_new = true
  start_date         = "2026-03-01T00:00:00Z"
  ending_type        = "never"

  human_cron = {
    time_period_type = "hours"
    time_period      = 1
    days             = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
  }
}

# Set server configuration (XSOAR 6 / XSOAR 8 SaaS only)
resource "cortex_server_config" "session_timeout" {
  key   = "session.timeout"
  value = "60"
}

# Configure password policy
resource "cortex_password_policy" "main" {
  min_length            = 12
  min_length_enabled    = true
  min_lowercase         = 1
  min_lowercase_enabled = true
  min_uppercase         = 1
  min_uppercase_enabled = true
  min_digits            = 1
  min_digits_enabled    = true
  min_special           = 1
  min_special_enabled   = true
}

# Store credentials
resource "cortex_credential" "service_account" {
  name     = "my-service-account"
  user     = "svc_user"
  password = var.service_password
}

# Manage a list (works on all platforms)
resource "cortex_list" "allowed_ips" {
  name = "AllowedIPs"
  type = "plain_text"
  data = "10.0.0.1\n10.0.0.2\n10.0.0.3"
}

# Configure integration instance
resource "cortex_integration_instance" "virustotal" {
  name             = "VirusTotal"
  integration_name = "VirusTotal"
  enabled          = true
  config = {
    "API Key"  = var.virustotal_api_key
    "useproxy" = "false"
  }
}
```

### 3. Apply

```bash
terraform init
terraform plan
terraform apply
```

## Resources

| Resource                         | Type       | Description                              | V6  | V8 OPP | V8 SaaS | XSIAM |
|----------------------------------|------------|------------------------------------------|-----|--------|---------|-------|
| `cortex_server_config`           | per-key    | Server configuration key/value pairs     | Y   | --     | Y       | --    |
| `cortex_marketplace_pack`        | per-pack   | Marketplace pack installation            | Y   | Y      | Y       | Y     |
| `cortex_integration_instance`    | per-inst   | Integration instance configuration       | Y   | Y      | Y       | Y     |
| `cortex_role`                    | per-role   | User roles and permissions               | Y   | RO     | RO      | RO    |
| `cortex_api_key`                 | per-key    | API key management                       | Y   | Y      | --      | --    |
| `cortex_job`                     | per-job    | Scheduled jobs                           | Y   | Y      | Y       | Y     |
| `cortex_preprocessing_rule`      | per-rule   | Incident pre-processing rules            | Y   | Y      | --      | Y     |
| `cortex_password_policy`         | singleton  | Password policy settings                 | Y   | Y      | Y       | Y     |
| `cortex_ha_group`                | per-group  | High availability groups                 | Y   | --     | --      | --    |
| `cortex_host`                    | per-host   | Server/engine hosts                      | Y   | --     | --      | --    |
| `cortex_account`                 | per-acct   | Multi-tenant accounts                    | Y   | --     | --      | --    |
| `cortex_credential`              | per-cred   | Stored credentials                       | Y   | Y      | Y       | Y     |
| `cortex_exclusion_list`          | per-entry  | Indicator exclusion list entries          | Y   | Y      | Y       | Y     |
| `cortex_backup_config`           | singleton  | Backup configuration                     | Y   | --     | --      | --    |
| `cortex_external_storage`        | per-store  | External storage (NFS/AWS/S3)            | --  | Y*     | --      | --    |
| `cortex_backup_schedule`         | per-sched  | Backup retention schedules               | --  | Y*     | --      | --    |
| `cortex_security_settings`       | singleton  | Security/authentication settings         | --  | Y*     | --      | --    |
| `cortex_list`                    | per-list   | Lists (IP lists, CSV, JSON, text)        | Y   | Y      | Y       | Y     |
| `cortex_correlation_rule`        | per-rule   | XSIAM correlation rules                  | --  | --     | --      | W     |
| `cortex_ioc_rule`                | per-rule   | XSIAM IOC rules                          | --  | --     | --      | W     |
| `cortex_edl`                     | singleton  | External Dynamic List config             | --  | --     | --      | W     |
| `cortex_vulnerability_scan_settings` | singleton | Vulnerability scan settings          | --  | --     | --      | W     |
| `cortex_agent_group`             | per-group  | Endpoint agent groups                    | --  | --     | --      | W     |
| `cortex_notification_rule`       | per-rule   | Alert notification/forwarding rules      | --  | --     | --      | W     |
| `cortex_bioc_rule`               | per-rule   | Behavioral IOC rules                     | --  | --     | --      | W     |
| `cortex_tim_rule`                | per-rule   | Threat Intelligence rules                | --  | --     | --      | W     |
| `cortex_fim_rule_group`          | per-group  | FIM rule groups                          | --  | --     | --      | W     |
| `cortex_fim_rule`                | per-rule   | File Integrity Monitoring rules          | --  | --     | --      | W     |
| `cortex_analytics_detector`      | per-rule   | Analytics detector overrides             | --  | --     | --      | W     |
| `cortex_attack_surface_rule`     | per-rule   | Attack surface rule overrides            | --  | --     | --      | W     |
| `cortex_device_control_class`    | per-class  | USB device control classes               | --  | --     | --      | W     |
| `cortex_custom_status`           | per-status | Custom alert/incident statuses           | --  | --     | --      | W     |
| `cortex_incident_domain`         | per-domain | Incident domain categories               | --  | --     | --      | W     |
| `cortex_rules_exception`         | per-rule   | Detection rule exceptions                | --  | --     | --      | W     |
| `cortex_parsing_rules`           | singleton  | XQL parsing rules                        | --  | --     | --      | W     |
| `cortex_data_modeling_rules`     | singleton  | XQL data modeling rules                  | --  | --     | --      | W     |
| `cortex_auto_upgrade_settings`   | singleton  | Collector auto-upgrade settings          | --  | --     | --      | W     |
| `cortex_collector_group`         | per-group  | XDR collector groups                     | --  | --     | --      | W     |
| `cortex_collector_distribution`  | per-dist   | XDR collector distribution packages      | --  | --     | --      | W     |
| `cortex_collector_profile`       | per-prof   | XDR collector profiles                   | --  | --     | --      | W     |
| `cortex_asm_asset_removal`       | bulk       | Bulk ASM asset removal (irreversible)    | --  | --     | --      | W     |

### Data Sources

| Data Source                      | Description                              | Availability |
|----------------------------------|------------------------------------------|:------------:|
| `cortex_datasets`                | List all datasets                        | XSIAM (W)    |
| `cortex_broker_vms`              | List broker VM devices                   | XSIAM (W)    |
| `cortex_collector_policies`      | List collector policies                  | XSIAM (W)    |

**Y** = full CRUD, **RO** = read-only, **--** = not available, **Y*** = requires session auth (`ui_url` + `username` + `password`), **W** = requires webapp session token

## Authentication

| Deployment   | Auth Method                                                         |
|--------------|---------------------------------------------------------------------|
| XSOAR 6      | `api_key` only (`Authorization` header)                             |
| XSOAR 8 OPP  | `api_key` + `auth_id` (`Authorization` + `x-xdr-auth-id` headers)  |
| XSOAR 8 OPP* | Session cookies via `ui_url` + `username` + `password` (webapp endpoints) |
| XSOAR 8 SaaS | `api_key` + `auth_id`; optionally `session_token` for webapp resources |
| XSIAM        | `api_key` + `auth_id`; optionally `session_token` for webapp resources |

*Session auth is only needed for `cortex_external_storage`, `cortex_backup_schedule`, and `cortex_security_settings`.

### Obtaining a Session Token (XSIAM / XSOAR 8 SaaS)

To use webapp-only resources on XSIAM or XSOAR 8 SaaS, you need a session token obtained from the browser:

1. Log into the XSIAM/XSOAR 8 SaaS UI in your browser
2. Open Developer Tools (F12) -> Application -> Cookies
3. Copy the value of the `app-proxy-hydra-prod-us` cookie (or `app-hub` cookie)
4. Set it as the `session_token` provider attribute or `CORTEX_SESSION_TOKEN` env var

## Architecture

```
provider/
  main.go                          # Entry point
  go.mod                           # Module: terraform-provider-cortex
  GNUmakefile                      # build, install, test, clean
  internal/
    provider/provider.go           # Provider config, version detection, backend selection
    providerdata/providerdata.go   # Shared ProviderData struct
    client/
      http.go                      # HTTP client with retry, TLS, auth
      errors.go                    # APIError, IsNotFound(), IsConflict()
      webapp.go                    # Session-authenticated webapp client (OPP + token)
    api/
      backend.go                   # XSOARBackend interface + data types
      v6/backend.go                # XSOAR 6 API implementation
      v8/backend.go                # XSOAR 8 / XSIAM API implementation (/xsoar/ prefix)
    resources/                     # One file per resource type (34 resources)
    datasources/                   # Data source implementations (3 data sources)
  examples/                        # Example .tf configurations
  tools/xsoar-export/              # Python export tool
```

### Design

The provider uses a **version-abstracted backend** pattern. All resources call the `XSOARBackend` interface -- never HTTP directly. The provider auto-detects the version and product mode via `GET /about` and selects the V6 or V8 backend implementation:

```
Provider --> detects version + productMode --> selects Backend (V6 or V8)
Resources --> call Backend interface --> Backend handles API specifics
```

XSIAM is detected via `productMode: "xsiam"` in the `/about` response and routes to the V8 backend, since XSIAM shares the same `/xsoar/` prefix API as XSOAR 8.

### Optimistic Concurrency

XSOAR uses a `version` field for optimistic locking. The provider tracks this automatically:
- **Create**: sends `version: -1` (new resource convention)
- **Update**: includes the current version from state
- **Conflict**: HTTP 400 on version mismatch

## Export Tool

The included Python tool exports an existing XSOAR/XSIAM configuration into Terraform `.tf` files:

```bash
cd tools/xsoar-export
pip install -r requirements.txt

# Export from XSOAR 6
python3 xsoar_export.py \
  --url https://xsoar.example.com \
  --api-key YOUR_API_KEY \
  --insecure \
  --output-dir ./exported

# Export from XSOAR 8
python3 xsoar_export.py \
  --url https://api-xsoar8.example.com \
  --api-key YOUR_API_KEY \
  --auth-id 9 \
  --insecure \
  --output-dir ./exported

# Export from XSIAM
python3 xsoar_export.py \
  --url https://api-mytenant.xdr.us.paloaltonetworks.com \
  --api-key YOUR_API_KEY \
  --auth-id YOUR_AUTH_ID \
  --insecure \
  --output-dir ./exported

# Export specific resource types only
python3 xsoar_export.py \
  --url https://xsoar.example.com \
  --api-key YOUR_API_KEY \
  --insecure \
  --resources marketplace,jobs,credentials \
  --output-dir ./exported
```

The export tool generates:
- One `.tf` file per resource type (e.g., `jobs.tf`, `credentials.tf`)
- `main.tf` with provider configuration
- `variables.tf` with all variable declarations
- `terraform.tfvars.example` template
- `import.sh` script with `terraform import` commands for all discovered resources

### Supported export types

`server_config`, `marketplace`, `integrations`, `roles`, `api_keys`, `jobs`, `preprocessing_rules`, `password_policy`, `credentials`, `exclusion_list`

## Development

### Building

```bash
make build      # Compile binary
make install    # Build + install to local Terraform plugins
make test       # Run unit tests
make testacc    # Run acceptance tests (requires TF_ACC=1)
make lint       # Run golangci-lint
make clean      # Remove compiled binary
```

### Running tests

```bash
# Unit tests
make test

# Acceptance tests (requires a live XSOAR instance)
export DEMISTO_BASE_URL="https://xsoar.example.com"
export DEMISTO_API_KEY="your-api-key"
export TF_ACC=1
make testacc
```

### Project conventions

- Built with [terraform-plugin-framework](https://developer.hashicorp.com/terraform/plugin/framework) v1.13.0 (not the legacy SDKv2)
- `ProviderData` lives in `internal/providerdata/` to avoid an import cycle between `provider` and `resources` packages
- Every resource implements `resource.Resource` + `resource.ResourceWithImportState`
- Resources read back state from the API after Create/Update for consistency
- 404 errors in Delete are handled gracefully (resource already gone)

## Debugging and Troubleshooting

### Enable Debug Logging

The provider uses Terraform's built-in logging framework. Set the `TF_LOG` environment variable to control log verbosity:

```bash
# Show provider debug logs (API requests, response status codes, version detection)
TF_LOG=DEBUG terraform plan

# Show full trace logs including request/response bodies (may contain sensitive data)
TF_LOG=TRACE terraform plan

# Write logs to a file for sharing
TF_LOG=TRACE TF_LOG_PATH=./terraform-debug.log terraform plan
```

### Log Levels

| Level   | What it shows                                                          |
|---------|------------------------------------------------------------------------|
| `ERROR` | API errors (4xx/5xx), redirect errors, exhausted retries               |
| `WARN`  | Retryable failures (5xx), version detection fallbacks, missing tokens  |
| `INFO`  | XSOAR version detected, deployment mode, product mode, session auth    |
| `DEBUG` | Every API request (method, path, attempt number, status code, body size) |
| `TRACE` | Full request and response bodies (truncated at 2KB/4KB respectively)   |

### Filter Logs to Provider Only

To see only the Cortex provider logs (excluding Terraform core noise):

```bash
TF_LOG_PROVIDER=TRACE terraform plan
TF_LOG_PROVIDER=TRACE TF_LOG_PATH=./provider-debug.log terraform plan
```

### Common Issues

**"Version Detection Failed"** -- The provider could not reach `/about` or `/xsoar/about`. Verify your `base_url` is correct and the instance is reachable. For XSOAR 8 and XSIAM, use the API URL (e.g., `https://api-xsoar8.example.com`), not the UI URL.

**"Webapp Session Auth Failed"** -- The provider could not log in via the UI URL. Verify `ui_url`, `username`, and `password`. This only affects `cortex_external_storage`, `cortex_backup_schedule`, and `cortex_security_settings`.

**"system/config is blocked on XSIAM"** -- The `cortex_server_config` resource is not available on XSIAM. The API blocks system/config for public API requests on XSIAM instances.

**"Missing start date for scheduler" (XSIAM)** -- XSIAM requires `start_date` and `human_cron` for scheduled jobs. Standard `cron` expressions are not supported on XSIAM.

**"Human cron is nil" (XSIAM)** -- XSIAM scheduled jobs must use `human_cron` instead of `cron`. See the job resource documentation for examples.

**HTTP 400 with "errOptimisticLock"** -- A concurrent modification changed the resource version. Run `terraform refresh` then retry.

**HTTP 401 Unauthorized** -- Check your `api_key` and `auth_id`. For XSOAR 8 and XSIAM, both are required.

**HTTP 405 Method Not Allowed** -- The resource is not available on this XSOAR version/deployment. For example, roles are read-only on XSOAR 8, and API keys are not available on XSOAR 8 SaaS.

**HTTP 303 Redirect** -- XSOAR returns 303 to signal a resource/endpoint is not available. The provider treats this as an error rather than following the redirect.

### Reporting Issues

When reporting an issue, please include the following information so it can be diagnosed quickly:

**1. Provider and XSOAR version**

```bash
# Provider version
terraform version

# XSOAR version (from the API)
curl -sk -H "Authorization: YOUR_API_KEY" https://YOUR_XSOAR_URL/about | python3 -m json.tool
# For XSOAR 8 / XSIAM, add: -H "x-xdr-auth-id: YOUR_AUTH_ID" and use /xsoar/about
```

**2. Terraform configuration** (sanitize credentials)

```bash
# Show the relevant resource block(s) from your .tf files
# Replace sensitive values with placeholders
```

**3. Full debug log**

```bash
TF_LOG_PROVIDER=TRACE TF_LOG_PATH=./debug.log terraform apply
# Then attach debug.log to the issue
```

> **IMPORTANT:** The trace log may contain sensitive data (API keys in headers, passwords in request bodies). Review and redact `"Authorization"` headers and any credential values before sharing.

**4. Terraform plan/apply output**

```bash
terraform plan 2>&1 | tee plan-output.txt
# or
terraform apply 2>&1 | tee apply-output.txt
```

**5. Expected vs actual behavior** -- What did you expect to happen, and what happened instead?

**6. Steps to reproduce** -- Minimal `.tf` configuration that triggers the issue.

### Issue Template

```
**Provider version:** (e.g., v0.2.0)
**XSOAR/XSIAM version:** (e.g., 8.13.0, productMode: xsiam, deploymentMode: saas)
**Terraform version:** (e.g., 1.7.0)
**OS:** (e.g., Ubuntu 22.04)

**Resource:** (e.g., cortex_job)
**Operation:** (e.g., create / update / delete / import)

**Terraform config:**
\`\`\`hcl
resource "cortex_job" "example" {
  name        = "test"
  playbook_id = "MyPlaybook"
  scheduled   = true
  cron        = "0 * * * *"
}
\`\`\`

**Error message:**
\`\`\`
<paste the error from terraform output>
\`\`\`

**Debug log:** (attach debug.log file)

**Expected behavior:**
<what you expected>

**Actual behavior:**
<what actually happened>

**Steps to reproduce:**
1. terraform init
2. terraform apply
3. <error occurs>
```

File issues at: [github.com/mdrobniu/terraform-provider-cortex/issues](https://github.com/mdrobniu/terraform-provider-cortex/issues)

## XSOAR / XSIAM API Notes

### XSOAR 6 endpoints

| Operation              | Method | Endpoint                                   |
|------------------------|--------|--------------------------------------------|
| Server info            | GET    | `/about`                                   |
| Server config          | GET    | `/system/config`                           |
| Server config update   | POST   | `/system/config`                           |
| Installed packs        | GET    | `/contentpacks/metadata/installed`         |
| Install packs          | POST   | `/contentpacks/marketplace/install`        |
| Integration search     | POST   | `/settings/integration/search`             |
| Integration upsert     | PUT    | `/settings/integration`                    |
| Jobs search            | POST   | `/jobs/search`                             |
| Job create             | POST   | `/jobs`                                    |
| Job update             | PUT    | `/jobs`                                    |
| Job delete             | DELETE | `/jobs/{id}`                               |
| Password policy        | GET/POST | `/settings/password-policy`              |
| Credentials list       | POST   | `/settings/credentials`                    |
| Credentials save       | POST   | `/settings/credentials/save`               |
| Credentials delete     | POST   | `/settings/credentials/delete`             |
| Exclusion list         | GET    | `/indicators/whitelisted`                  |
| Exclusion add/update   | POST   | `/indicators/whitelist/update`             |
| Exclusion remove       | POST   | `/indicators/whitelist/remove`             |
| Lists get              | GET    | `/lists/download/{name}`                   |
| Lists save             | POST   | `/lists/save`                              |
| Lists delete           | POST   | `/lists/delete`                            |

### XSOAR 8 / XSIAM differences

- All endpoints are prefixed with `/xsoar/` (e.g., `/xsoar/about`, `/xsoar/jobs/search`)
- Credentials save uses `PUT` instead of `POST`
- Job update uses `POST` instead of `PUT`
- Roles are read-only (managed at the XDR platform level)
- HA groups, hosts, accounts, and backup config are not available
- SaaS deployments do not support API key management via API
- **XSIAM only:** `system/config` is blocked for public API requests
- **XSIAM only:** Jobs require `humanCron` + `startDate` instead of standard `cron`

## Disclaimer & Limitation of Liability

THIS SOFTWARE IS PROVIDED "AS IS" AND "AS AVAILABLE", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT.

THE ENTIRE RISK AS TO THE QUALITY, PERFORMANCE, AND RESULTS OF USING THIS
SOFTWARE REMAINS WITH YOU. THE AUTHOR(S) AND CONTRIBUTOR(S) SHALL NOT BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, CONSEQUENTIAL, OR
PUNITIVE DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, PROFITS, OR BUSINESS INTERRUPTION; SYSTEM
DOWNTIME; SECURITY BREACHES; LOSS OF OR DAMAGE TO CONFIGURATION; OR ANY
FINANCIAL LOSS) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.

This provider interacts directly with your Cortex XSOAR/XSIAM instance and can create,
modify, and delete configuration including but not limited to security policies,
credentials, integration instances, jobs, and access controls. Misconfiguration
may result in service disruption, data loss, or security exposure. You are solely
responsible for validating all Terraform plans before applying them and for
maintaining appropriate backups of your XSOAR/XSIAM configuration.

This project is not affiliated with, endorsed by, or sponsored by Palo Alto
Networks, Inc. Cortex XSOAR and Cortex XSIAM are trademarks of Palo Alto Networks, Inc.

## License

MIT License. See [LICENSE](LICENSE) for the full text.
