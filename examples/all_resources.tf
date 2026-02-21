# Advanced Example: All Resources with All Parameters
# This file demonstrates every resource type with all available attributes.
#
# Note: Not all resources are available on every deployment.
# See the compatibility matrix in README.md for details.

terraform {
  required_providers {
    cortex = {
      source  = "registry.terraform.io/mdrobniu/cortex"
      version = "~> 0.2"
    }
  }
}

provider "cortex" {
  base_url = var.base_url
  api_key  = var.api_key
  auth_id  = var.auth_id
  insecure = var.insecure

  # OPP session auth (for external_storage, backup_schedule, security_settings)
  ui_url   = var.ui_url
  username = var.username
  password = var.password

  # XSIAM/SaaS session token (for future webapp resources)
  session_token = var.session_token
}

# --- Variables ---

variable "base_url" {
  description = "API base URL"
  type        = string
}

variable "api_key" {
  description = "API key"
  type        = string
  sensitive   = true
}

variable "auth_id" {
  description = "Auth ID for XSOAR 8 / XSIAM"
  type        = string
  default     = ""
}

variable "insecure" {
  description = "Skip TLS verification"
  type        = bool
  default     = true
}

variable "ui_url" {
  description = "UI URL for OPP session auth"
  type        = string
  default     = ""
}

variable "username" {
  description = "Username for OPP session auth"
  type        = string
  default     = ""
}

variable "password" {
  description = "Password for OPP session auth"
  type        = string
  sensitive   = true
  default     = ""
}

variable "session_token" {
  description = "Session token for XSIAM/SaaS webapp auth"
  type        = string
  sensitive   = true
  default     = ""
}

variable "service_password" {
  description = "Password for service credential"
  type        = string
  sensitive   = true
  default     = "changeme"
}

variable "virustotal_key" {
  description = "VirusTotal API key"
  type        = string
  sensitive   = true
  default     = "changeme"
}

# =============================================================================
# Resources available on ALL platforms (V6, V8 OPP, V8 SaaS, XSIAM)
# =============================================================================

# --- cortex_password_policy (singleton) ---
# All attributes shown with their default values

resource "cortex_password_policy" "main" {
  enabled                  = true   # Enable password policy enforcement
  min_password_length      = 12     # Minimum password length
  min_lowercase_chars      = 1      # Minimum lowercase characters
  min_uppercase_chars      = 1      # Minimum uppercase characters
  min_digits_or_symbols    = 1      # Minimum digits or special characters
  max_failed_login_attempts = 5     # Lock after N failed login attempts
  self_unlock_after_minutes = 30    # Auto-unlock after N minutes (0 = manual)
  expire_after             = 90     # Password expires after N months (0 = never)
  prevent_repetition       = true   # Prevent password reuse
}

# --- cortex_credential (per-cred) ---

resource "cortex_credential" "example" {
  name     = "my-service-account"   # Unique credential name (used as ID)
  user     = "svc_user"             # Username
  password = var.service_password   # Password (write-only, not returned by API)
  comment  = "Service account for automation"  # Optional description
}

# --- cortex_job (per-job) ---

# Job with cron (XSOAR 6/8)
resource "cortex_job" "cron_job" {
  name               = "Daily Cleanup"           # Job display name
  playbook_id        = "CloseStaleIncidents"     # Playbook to execute
  type               = "Housekeeping"            # Incident type
  scheduled          = true                       # Enable scheduling
  cron               = "0 2 * * *"               # Cron expression (every day at 2 AM)
  recurrent          = true                       # Repeat on schedule
  should_trigger_new = true                       # Create new incident each run
  tags               = ["maintenance", "nightly"] # Associated tags
}

# Job with human_cron (XSIAM)
resource "cortex_job" "human_cron_job" {
  name               = "Hourly Feed Check"
  type               = "Unclassified"
  scheduled          = true
  recurrent          = true
  should_trigger_new = true
  start_date         = "2026-03-01T00:00:00Z"    # ISO 8601 start date (required on XSIAM)
  ending_date        = "2026-12-31T23:59:59Z"    # ISO 8601 end date (optional)
  ending_type        = "by_date"                  # "never" or "by_date"

  human_cron = {
    time_period_type = "hours"                    # minutes, hours, days, weeks, months
    time_period      = 1                          # Interval value
    days             = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]  # Days to run
  }
}

# --- cortex_exclusion_list (per-entry) ---

# CIDR exclusion
resource "cortex_exclusion_list" "cidr" {
  value  = "10.0.0.0/8"         # IP/CIDR/domain/regex to exclude
  type   = "CIDR"               # "standard", "CIDR", or "regex"
  reason = "Internal network"   # Human-readable reason
}

# Standard domain exclusion
resource "cortex_exclusion_list" "domain" {
  value  = "example.com"
  type   = "standard"
  reason = "Corporate domain"
}

# Regex exclusion
resource "cortex_exclusion_list" "regex" {
  value  = "^host-[0-9]+\\.internal$"
  type   = "regex"
  reason = "Internal hostname pattern"
}

# --- cortex_list (per-list) ---

# Plain text list
resource "cortex_list" "text_list" {
  name = "AllowedIPs"           # List name (also serves as ID, forces replacement)
  type = "plain_text"           # plain_text, json, html, markdown, css
  data = <<-EOT
    10.0.0.1
    10.0.0.2
    192.168.1.0/24
  EOT
}

# JSON list
resource "cortex_list" "json_list" {
  name = "AppConfig"
  type = "json"
  data = jsonencode({
    max_retries = 3
    timeout     = 30
    enabled     = true
  })
}

# Markdown list
resource "cortex_list" "markdown_list" {
  name = "Runbook"
  type = "markdown"
  data = <<-EOT
    # Incident Runbook
    1. Triage the alert
    2. Isolate affected hosts
    3. Collect forensic evidence
  EOT
}

# --- cortex_marketplace_pack (per-pack) ---

resource "cortex_marketplace_pack" "example" {
  pack_id = "CommonScripts"     # Marketplace pack ID
  version = "1.13.38"           # Pack version to install
}

# --- cortex_integration_instance (per-inst) ---

resource "cortex_integration_instance" "example" {
  name             = "VirusTotal-Prod"     # Instance display name
  integration_name = "VirusTotal"          # Integration brand/type
  enabled          = true                   # Enable the instance
  engine_group     = ""                     # Engine group (leave empty for default)
  config = {                                # Integration-specific configuration
    "API Key"  = var.virustotal_key
    "useproxy" = "false"
  }
  propagation_labels = []                   # Propagation labels for multi-tenant
}

# --- cortex_role (per-role, read-only on V8/XSIAM) ---

resource "cortex_role" "analyst" {
  name = "SOC Analyst"           # Role display name
  permissions = {                # Permission groups -> list of permissions
    "scripts" = ["run"]
    "incidents" = ["view", "edit", "close"]
  }
}

# =============================================================================
# Resources available on XSOAR 6 and XSOAR 8 SaaS only
# =============================================================================

# --- cortex_server_config (per-key) ---
# NOT available on XSIAM (blocked for public API requests)

resource "cortex_server_config" "session_timeout" {
  key   = "session.timeout"     # Configuration key
  value = "60"                  # Configuration value (always a string)
}

# =============================================================================
# Resources available on XSOAR 6 only
# =============================================================================

# --- cortex_api_key (per-key) ---
# NOT available on XSOAR 8 SaaS or XSIAM

resource "cortex_api_key" "ci" {
  name = "ci-pipeline"          # Key display name
}

# --- cortex_preprocessing_rule (per-rule) ---
# Available on XSOAR 6 and XSIAM

resource "cortex_preprocessing_rule" "dedup" {
  name       = "Deduplicate Alerts"   # Rule display name
  enabled    = true                    # Enable the rule
  action     = "drop"                  # "drop", "run_script", or "link"
  rules_json = jsonencode({            # Filter rules as JSON
    "FILTER" = {
      "filter" = {
        "AND" = [{
          "SEARCH_FIELD" = "name"
          "SEARCH_TYPE"  = "EQ"
          "SEARCH_VALUE" = ""
        }]
      }
    }
  })
}

# --- cortex_ha_group (per-group, V6 only) ---

resource "cortex_ha_group" "primary" {
  name                 = "Primary HA Group"
  elasticsearch_url    = "https://es.example.com:9200"
  elastic_index_prefix = "demisto"
}

# --- cortex_host (per-host, V6 only) ---
# Hosts are typically managed outside Terraform
# This resource is for importing existing hosts

# --- cortex_account (per-acct, V6 only) ---

resource "cortex_account" "tenant_a" {
  name          = "TenantA"
  display_name  = "Tenant A - Production"
  host_group_id = cortex_ha_group.primary.id
  roles         = ["SOC Analyst"]
}

# --- cortex_backup_config (singleton, V6 only) ---

resource "cortex_backup_config" "main" {
  enabled        = true               # Enable automatic backups
  schedule_cron  = "0 3 * * *"        # Backup schedule (daily at 3 AM)
  retention_days = 30                  # Keep backups for 30 days
  path           = "/var/lib/demisto/backup"  # Backup storage path
}

# =============================================================================
# Resources available on XSOAR 8 OPP only (require session auth)
# =============================================================================

# --- cortex_external_storage (per-store, V8 OPP + session auth) ---

resource "cortex_external_storage" "nfs_backup" {
  name         = "NFS Backup Storage"
  storage_type = "nfs"                # "nfs", "aws", or "s3compatible"
  connection_details = {
    "host" = "nfs.example.com"
    "path" = "/exports/xsoar-backup"
  }
}

resource "cortex_external_storage" "s3_archive" {
  name         = "S3 Archive"
  storage_type = "aws"
  connection_details = {
    "bucket"     = "xsoar-archive"
    "region"     = "us-east-1"
    "access_key" = "AKIAIOSFODNN7EXAMPLE"
    "secret_key" = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}

# --- cortex_backup_schedule (per-sched, V8 OPP + session auth) ---
# Note: No update API -- changes force replacement

resource "cortex_backup_schedule" "daily" {
  storage_id       = cortex_external_storage.nfs_backup.id
  retention_period = 30               # Keep backups for 30 days
  relative_path    = "daily"          # Subdirectory in storage

  human_cron = {
    time_period_type = "hours"
    time_period      = 24
    days             = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
  }
}

# --- cortex_security_settings (singleton, V8 OPP + session auth) ---

resource "cortex_security_settings" "main" {
  user_login_expiration      = 30     # Session expires after N minutes
  auto_logout_enabled        = true   # Enable auto-logout
  auto_logout_time           = 15     # Auto-logout after N minutes idle
  dashboard_expiration       = 60     # Dashboard session expiration (minutes)
  approved_ip_ranges         = ["10.0.0.0/8", "172.16.0.0/12"]  # Allowed IP ranges
  approved_domains           = ["example.com"]                    # Allowed email domains
  approved_mailing_domains   = ["example.com"]                    # Allowed mailing domains
  time_to_inactive_users     = 90     # Days before marking users inactive
  inactive_users_is_enable   = true   # Enable inactive user detection
  external_ip_monitoring     = true   # Monitor external IP access
  limit_api_access           = false  # Limit API access to approved IPs
}

# =============================================================================
# XSIAM Configuration Resources (require session_token)
# =============================================================================

# --- cortex_parsing_rules (singleton) ---
# Manages the full text of XQL parsing rules. Uses hash-based optimistic locking.

resource "cortex_parsing_rules" "main" {
  text = <<-EOT
    [INGEST:vendor="custom", product="myapp", target_dataset="custom_myapp", no_hit=drop]
    alter _raw_log = to_string(_raw_log)
    | alter src_ip = arrayindex(regextract(_raw_log, "src=(\d+\.\d+\.\d+\.\d+)"), 0);
  EOT
}

# --- cortex_data_modeling_rules (singleton) ---
# Manages the full text of XQL data modeling rules. Uses hash-based optimistic locking.

resource "cortex_data_modeling_rules" "main" {
  text = <<-EOT
    [MODEL: dataset="custom_myapp"]
    alter xdm.event.type = "APP_EVENT"
    | alter xdm.source.ipv4 = src_ip;
  EOT
}

# --- cortex_auto_upgrade_settings (singleton) ---
# Configures XDR collector auto-upgrade global settings.
# Delete is a no-op (settings persist on the tenant).

resource "cortex_auto_upgrade_settings" "main" {
  batch_size = 500               # Agents per upgrade batch
  start_time = "02:00"           # Upgrade window start (optional, null = anytime)
  end_time   = "06:00"           # Upgrade window end (optional, null = anytime)
  days       = ["Saturday", "Sunday"]  # Days for upgrades (optional, null = all days)
}

# --- cortex_collector_group (per-group) ---
# No update API; all mutable fields force replacement.

resource "cortex_collector_group" "example" {
  name        = "Syslog Collectors"        # Group display name (ForceNew)
  description = "Syslog data collectors"   # Description (ForceNew)
  type        = "STATIC"                   # "STATIC" or "DYNAMIC" (ForceNew)
  # filter    = jsonencode({...})          # JSON filter for DYNAMIC groups (ForceNew)
}

# --- cortex_collector_distribution (per-dist) ---
# No update API; all fields force replacement. Delete removes the distribution.

resource "cortex_collector_distribution" "example" {
  name          = "Linux Collector v1.5"    # Distribution name (ForceNew)
  description   = "Production Linux pkg"   # Description (ForceNew)
  agent_version = "1.5.1.2048"             # Collector agent version (ForceNew)
  platform      = "AGENT_OS_LINUX"         # AGENT_OS_WINDOWS or AGENT_OS_LINUX (ForceNew)
  package_type  = "SCOUTER_INSTALLER"      # Package type (default: SCOUTER_INSTALLER)
}

# --- cortex_collector_profile (per-profile) ---
# Create-only: no update or delete API. Delete removes from Terraform state only.

resource "cortex_collector_profile" "example" {
  name         = "Custom Linux Profile"             # Profile name (ForceNew)
  description  = "Custom syslog config"             # Description (ForceNew)
  platform     = "AGENT_OS_LINUX"                   # AGENT_OS_WINDOWS or AGENT_OS_LINUX (ForceNew)
  profile_type = "STANDARD"                         # Profile type (default: STANDARD)
  is_default   = false                              # Whether this is the default profile
  modules      = "IyBiYXNlNjQtZW5jb2RlZCBZQU1M"   # Base64-encoded YAML modules (ForceNew)
}

# --- cortex_asm_asset_removal (bulk, irreversible) ---
# Fire-and-forget: assets removed on create. Delete is no-op.
# WARNING: Asset removal is irreversible. terraform destroy will NOT restore assets.

# resource "cortex_asm_asset_removal" "decommissioned" {
#   assets = [
#     {
#       asset_type = "Domain"                  # Domain, IP_RANGE, or Certificate
#       asset_name = "old-app.example.com"     # Asset identifier
#     },
#     {
#       asset_type = "IP_RANGE"
#       asset_name = "10.99.0.0/16"
#     }
#   ]
# }

# =============================================================================
# XSIAM Data Sources (read-only, require session_token)
# =============================================================================

data "cortex_datasets" "all" {}

data "cortex_broker_vms" "all" {}

data "cortex_collector_policies" "all" {}
