# Terraform Provider for Cortex XSOAR

A Terraform provider for managing [Palo Alto Cortex XSOAR](https://www.paloaltonetworks.com/cortex/xsoar) instance configuration as code. Supports XSOAR 6, XSOAR 8 On-Prem/Private (OPP), and XSOAR 8 SaaS deployments.

## Features

- **16 resources** covering the full XSOAR configuration surface
- **Multi-version support** -- automatically detects XSOAR 6 vs 8 and uses the correct API
- **Deployment-mode aware** -- handles XSOAR 8 OPP and SaaS differences transparently
- **Session auth for OPP** -- optional webapp login for managing external storage and backup schedules
- **Export tool** -- Python utility to export existing XSOAR configuration into `.tf` files
- **Drift detection** -- reads back state from the API after every apply to detect out-of-band changes

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/dl/) >= 1.22 (for building from source)
- A Cortex XSOAR instance (v6 or v8) with API key access

## Installation

### Build from source

```bash
git clone https://github.com/mdrobniu/terraform-provider-cortex.git
cd terraform-provider-cortex
make install
```

This builds the binary and copies it to `~/.terraform.d/plugins/registry.terraform.io/warlock/cortex/0.1.0/linux_amd64/`.

## Quick Start

### 1. Configure the provider

```hcl
terraform {
  required_providers {
    cortex = {
      source  = "registry.terraform.io/warlock/cortex"
      version = "~> 0.1"
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
```

All provider arguments can also be set via environment variables:

| Argument   | Environment Variable  | Description                              |
|------------|-----------------------|------------------------------------------|
| `base_url` | `DEMISTO_BASE_URL`    | XSOAR API base URL                       |
| `api_key`  | `DEMISTO_API_KEY`     | API key for authentication               |
| `auth_id`  | `DEMISTO_AUTH_ID`     | Auth ID header for XSOAR 8               |
| `insecure` | `DEMISTO_INSECURE`    | Skip TLS certificate verification        |
| `ui_url`   | `XSOAR_UI_URL`        | UI URL for XSOAR 8 OPP session auth      |
| `username` | `XSOAR_USERNAME`      | Username for OPP session auth            |
| `password` | `XSOAR_PASSWORD`      | Password for OPP session auth            |

### 2. Create resources

```hcl
# Install a marketplace pack
resource "cortex_marketplace_pack" "common_scripts" {
  pack_id = "CommonScripts"
  version = "1.13.38"
}

# Create a scheduled job
resource "cortex_job" "daily_cleanup" {
  name        = "Daily Incident Cleanup"
  playbook_id = "CloseStaleIncidents"
  scheduled   = true
  cron        = "0 2 * * *"
  recurrent   = true
}

# Set server configuration
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

| Resource                         | Type       | Description                              | V6 | V8 OPP | V8 SaaS |
|----------------------------------|------------|------------------------------------------|----|--------|---------|
| `cortex_server_config`           | per-key    | Server configuration key/value pairs     | Y  | --     | Y       |
| `cortex_marketplace_pack`        | per-pack   | Marketplace pack installation            | Y  | Y      | Y       |
| `cortex_integration_instance`    | per-inst   | Integration instance configuration       | Y  | Y      | Y       |
| `cortex_role`                    | per-role   | User roles and permissions               | Y  | RO     | RO      |
| `cortex_api_key`                 | per-key    | API key management                       | Y  | Y      | --      |
| `cortex_job`                     | per-job    | Scheduled jobs                           | Y  | Y      | Y       |
| `cortex_preprocessing_rule`      | per-rule   | Incident pre-processing rules            | Y  | Y      | --      |
| `cortex_password_policy`         | singleton  | Password policy settings                 | Y  | Y      | Y       |
| `cortex_ha_group`                | per-group  | High availability groups                 | Y  | --     | --      |
| `cortex_host`                    | per-host   | Server/engine hosts                      | Y  | --     | --      |
| `cortex_account`                 | per-acct   | Multi-tenant accounts                    | Y  | --     | --      |
| `cortex_credential`              | per-cred   | Stored credentials                       | Y  | Y      | Y       |
| `cortex_exclusion_list`          | per-entry  | Indicator exclusion list entries          | Y  | Y      | Y       |
| `cortex_backup_config`           | singleton  | Backup configuration                     | Y  | --     | --      |
| `cortex_external_storage`        | per-store  | External storage (NFS/AWS/S3)            | -- | Y*     | --      |
| `cortex_backup_schedule`         | per-sched  | Backup retention schedules               | -- | Y*     | --      |

**Y** = full CRUD, **RO** = read-only, **--** = not available, **Y*** = requires session auth (`ui_url` + `username` + `password`)

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
      webapp.go                    # Session-authenticated webapp client (OPP)
    api/
      backend.go                   # XSOARBackend interface + data types
      v6/backend.go                # XSOAR 6 API implementation
      v8/backend.go                # XSOAR 8 API implementation (/xsoar/ prefix)
    resources/                     # One file per resource type
  examples/                        # Example .tf configurations
  tools/xsoar-export/              # Python export tool
```

### Design

The provider uses a **version-abstracted backend** pattern. All resources call the `XSOARBackend` interface -- never HTTP directly. The provider auto-detects the XSOAR version via `GET /about` and selects the V6 or V8 backend implementation:

```
Provider --> detects version --> selects Backend (V6 or V8)
Resources --> call Backend interface --> Backend handles API specifics
```

### Authentication

| Deployment   | Auth Method                                                    |
|--------------|----------------------------------------------------------------|
| XSOAR 6      | `Authorization: <api_key>` header                             |
| XSOAR 8      | `Authorization: <api_key>` + `x-xdr-auth-id: <id>` headers   |
| XSOAR 8 OPP* | Session cookies via username/password login (webapp endpoints) |

*Session auth is only needed for external storage and backup schedule management, which use the `/api/webapp/` endpoints on the UI domain.

### Optimistic Concurrency

XSOAR uses a `version` field for optimistic locking. The provider tracks this automatically:
- **Create**: sends `version: -1` (new resource convention)
- **Update**: includes the current version from state
- **Conflict**: HTTP 400 on version mismatch

## Export Tool

The included Python tool exports an existing XSOAR configuration into Terraform `.tf` files:

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

## XSOAR API Notes

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

### XSOAR 8 differences

- All endpoints are prefixed with `/xsoar/` (e.g., `/xsoar/about`, `/xsoar/jobs/search`)
- Credentials save uses `PUT` instead of `POST`
- Job update uses `POST` instead of `PUT`
- Roles are read-only (managed at the XDR platform level)
- HA groups, hosts, accounts, and backup config are not available
- SaaS deployments do not support API key management or preprocessing rules via API

## License

This project is provided as-is for managing Cortex XSOAR instances via Terraform.
