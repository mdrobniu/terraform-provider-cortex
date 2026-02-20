# Settings Migration Example
# This file demonstrates migrating configuration between XSOAR/XSIAM instances.
#
# Usage:
#   1. Export from source instance using the xsoar-export tool:
#      python3 tools/xsoar-export/xsoar_export.py \
#        --url https://source-xsoar.example.com \
#        --api-key SOURCE_KEY --insecure --output-dir ./exported
#
#   2. Copy the exported .tf files and adapt them for the target instance.
#      Alternatively, use this template to manually define the resources
#      you want to migrate.
#
#   3. Point the provider at the target instance and run terraform apply.
#
# This example shows migrating:
#   - Password policy
#   - Credentials
#   - Exclusion list entries
#   - Scheduled jobs
#   - Lists
#   - Marketplace packs
#   - Integration instances
#
# Works across deployment types:
#   XSOAR 6 -> XSOAR 8, XSOAR 8 -> XSIAM, XSOAR 6 -> XSIAM, etc.
#
# Note: Some resources are deployment-specific. For example:
#   - server_config is not available on XSIAM
#   - human_cron is required on XSIAM (instead of cron)
#   - api_key is not available on XSOAR 8 SaaS or XSIAM

terraform {
  required_providers {
    cortex = {
      source  = "registry.terraform.io/mdrobniu/cortex"
      version = "~> 0.2"
    }
  }
}

provider "cortex" {
  base_url = var.target_url
  api_key  = var.target_api_key
  auth_id  = var.target_auth_id
  insecure = true
}

variable "target_url" {
  description = "Target XSOAR/XSIAM API URL"
  type        = string
}

variable "target_api_key" {
  description = "Target API key"
  type        = string
  sensitive   = true
}

variable "target_auth_id" {
  description = "Target auth ID (leave empty for XSOAR 6)"
  type        = string
  default     = ""
}

# --- Variables for sensitive values ---

variable "cred_passwords" {
  description = "Map of credential name to password"
  type        = map(string)
  sensitive   = true
  default     = {}
}

variable "integration_keys" {
  description = "Map of integration name to API key"
  type        = map(string)
  sensitive   = true
  default     = {}
}

# --- Password Policy (migrated from source) ---

resource "cortex_password_policy" "migrated" {
  min_length                  = 12
  min_length_enabled          = true
  min_lowercase               = 1
  min_lowercase_enabled       = true
  min_uppercase               = 1
  min_uppercase_enabled       = true
  min_digits                  = 1
  min_digits_enabled          = true
  min_special                 = 1
  min_special_enabled         = true
  max_failed_attempts         = 5
  max_failed_attempts_enabled = true
  expiration_days             = 90
  expiration_days_enabled     = true
}

# --- Credentials (migrated from source) ---

locals {
  credentials = {
    "svc-ticketing" = {
      user    = "ticketing_api"
      comment = "Ticketing system service account"
    }
    "svc-siem" = {
      user    = "siem_collector"
      comment = "SIEM data collector"
    }
    "svc-enrichment" = {
      user    = "enrichment_svc"
      comment = "Threat intel enrichment service"
    }
  }
}

resource "cortex_credential" "migrated" {
  for_each = local.credentials

  name     = each.key
  user     = each.value.user
  password = lookup(var.cred_passwords, each.key, "CHANGE_ME")
  comment  = each.value.comment
}

# --- Exclusion List (migrated from source) ---

locals {
  exclusions = {
    "internal_10" = {
      value  = "10.0.0.0/8"
      type   = "CIDR"
      reason = "Internal RFC 1918 range"
    }
    "internal_172" = {
      value  = "172.16.0.0/12"
      type   = "CIDR"
      reason = "Internal RFC 1918 range"
    }
    "internal_192" = {
      value  = "192.168.0.0/16"
      type   = "CIDR"
      reason = "Internal RFC 1918 range"
    }
    "corp_domain" = {
      value  = "example.com"
      type   = "standard"
      reason = "Corporate domain"
    }
  }
}

resource "cortex_exclusion_list" "migrated" {
  for_each = local.exclusions

  value  = each.value.value
  type   = each.value.type
  reason = each.value.reason
}

# --- Scheduled Jobs (migrated from source) ---
# Note: If migrating to XSIAM, replace 'cron' with 'human_cron' + 'start_date'

resource "cortex_job" "daily_cleanup" {
  name               = "Daily Incident Cleanup"
  playbook_id        = "CloseStaleIncidents"
  type               = "Unclassified"
  scheduled          = true
  cron               = "0 2 * * *"
  recurrent          = true
  should_trigger_new = true
}

resource "cortex_job" "weekly_report" {
  name               = "Weekly Security Report"
  playbook_id        = "GenerateSecurityReport"
  type               = "Unclassified"
  scheduled          = true
  cron               = "0 8 * * 1"
  recurrent          = true
  should_trigger_new = true
  tags               = ["reporting", "weekly"]
}

# --- Lists (migrated from source) ---

resource "cortex_list" "allowed_senders" {
  name = "AllowedEmailSenders"
  type = "plain_text"
  data = <<-EOT
    noreply@example.com
    alerts@monitoring.example.com
    security@partner.net
  EOT
}

resource "cortex_list" "severity_mapping" {
  name = "SeverityMapping"
  type = "json"
  data = jsonencode({
    critical = 4
    high     = 3
    medium   = 2
    low      = 1
    info     = 0
  })
}

# --- Marketplace Packs (migrated from source) ---

locals {
  packs = {
    "CommonScripts"   = "1.13.38"
    "CommonPlaybooks" = "2.6.23"
    "Base"            = "1.33.51"
    "rasterize"       = "1.3.3"
    "Phishing"        = "3.6.17"
  }
}

resource "cortex_marketplace_pack" "migrated" {
  for_each = local.packs

  pack_id = each.key
  version = each.value
}

# --- Integration Instances (migrated from source) ---

resource "cortex_integration_instance" "virustotal" {
  name             = "VirusTotal"
  integration_name = "VirusTotal"
  enabled          = true
  config = {
    "API Key"  = lookup(var.integration_keys, "virustotal", "CHANGE_ME")
    "useproxy" = "false"
  }
}
