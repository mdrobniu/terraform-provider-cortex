# XSIAM Configuration Example
# This file demonstrates managing an XSIAM instance with the Cortex provider.

terraform {
  required_providers {
    cortex = {
      source  = "registry.terraform.io/mdrobniu/cortex"
      version = "~> 0.2"
    }
  }
}

provider "cortex" {
  base_url = var.xsiam_api_url
  api_key  = var.xsiam_api_key
  auth_id  = var.xsiam_auth_id
  insecure = true
}

variable "xsiam_api_url" {
  description = "XSIAM API URL (e.g., https://api-xsiam.xdr.us.paloaltonetworks.com)"
  type        = string
}

variable "xsiam_api_key" {
  description = "XSIAM API key"
  type        = string
  sensitive   = true
}

variable "xsiam_auth_id" {
  description = "XSIAM auth ID"
  type        = string
}

# --- Password Policy ---

resource "cortex_password_policy" "main" {
  min_length            = 14
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

# --- Credentials ---

variable "svc_password" {
  description = "Service account password"
  type        = string
  sensitive   = true
}

resource "cortex_credential" "automation_svc" {
  name     = "automation-service"
  user     = "automation_user"
  password = var.svc_password
  comment  = "Used by XSIAM automation playbooks"
}

# --- Scheduled Jobs (XSIAM uses human_cron) ---

# Run every hour, all days
resource "cortex_job" "hourly_feed" {
  name               = "Hourly Feed Ingestion"
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

# Run every 30 minutes, weekdays only
resource "cortex_job" "business_check" {
  name               = "Business Hours Health Check"
  type               = "Unclassified"
  scheduled          = true
  recurrent          = true
  should_trigger_new = true
  start_date         = "2026-01-01T08:00:00Z"
  ending_type        = "never"

  human_cron = {
    time_period_type = "minutes"
    time_period      = 30
    days             = ["MON", "TUE", "WED", "THU", "FRI"]
  }
}

# Run every 2 hours with an end date
resource "cortex_job" "temp_monitoring" {
  name               = "Temporary Monitoring"
  type               = "Unclassified"
  scheduled          = true
  recurrent          = true
  should_trigger_new = true
  start_date         = "2026-03-01T00:00:00Z"
  ending_date        = "2026-06-01T00:00:00Z"
  ending_type        = "by_date"

  human_cron = {
    time_period_type = "hours"
    time_period      = 2
    days             = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"]
  }
}

# --- Exclusion List ---

resource "cortex_exclusion_list" "internal_cidr" {
  value  = "10.0.0.0/8"
  type   = "CIDR"
  reason = "Internal network range"
}

resource "cortex_exclusion_list" "corporate_domain" {
  value  = "corp.example.com"
  type   = "standard"
  reason = "Corporate domain"
}

# --- Lists ---

resource "cortex_list" "allowed_ips" {
  name = "AllowedIPs"
  type = "plain_text"
  data = <<-EOT
    10.0.0.1
    10.0.0.2
    172.16.0.0/12
    192.168.1.0/24
  EOT
}

resource "cortex_list" "config" {
  name = "AutomationConfig"
  type = "json"
  data = jsonencode({
    max_retries     = 3
    timeout_seconds = 60
    alert_threshold = 100
    enabled         = true
  })
}

# --- Marketplace Packs ---

resource "cortex_marketplace_pack" "common_scripts" {
  pack_id = "CommonScripts"
  version = "1.13.38"
}

resource "cortex_marketplace_pack" "common_playbooks" {
  pack_id = "CommonPlaybooks"
  version = "2.6.23"
}
