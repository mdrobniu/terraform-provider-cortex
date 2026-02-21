# XSIAM Configuration Example
# This file demonstrates managing an XSIAM instance with the Cortex provider.
# XSIAM webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

terraform {
  required_providers {
    cortex = {
      source  = "registry.terraform.io/mdrobniu/cortex"
      version = "~> 0.2"
    }
  }
}

provider "cortex" {
  base_url      = var.xsiam_api_url
  api_key       = var.xsiam_api_key
  auth_id       = var.xsiam_auth_id
  insecure      = true
  session_token = var.session_token # Required for webapp resources below
}

variable "session_token" {
  description = "Session token for XSIAM webapp API access (from cortex-login or browser DevTools)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "xsiam_api_url" {
  description = "XSIAM API URL (e.g., https://api-mytenant.xdr.us.paloaltonetworks.com)"
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
  enabled               = true
  min_password_length   = 14
  min_lowercase_chars   = 1
  min_uppercase_chars   = 1
  min_digits_or_symbols = 1
  prevent_repetition    = true
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

# ============================================================================
# XSIAM Webapp Resources (require session_token)
# Webapp API endpoints based on XSIAM V3.4; may differ on other versions.
# ============================================================================

# --- EDL (External Dynamic List) ---

resource "cortex_edl" "main" {
  enabled  = true
  username = "edl_consumer"
  password = var.edl_password
}

# --- Vulnerability Scan Settings ---

resource "cortex_vulnerability_scan_settings" "main" {
  eula_accepted           = true
  new_tests_enabled       = true
  pause_testing           = false
  run_tests_on_all_services = false
  intrusive_level         = 1
}

# --- Agent Groups ---

resource "cortex_agent_group" "web_servers" {
  name        = "Web Servers"
  description = "Production web server endpoints"
  type        = "DYNAMIC"
  filter = jsonencode({
    field    = "hostname"
    operator = "contains"
    value    = "web"
  })
}

# --- Notification Rules ---

resource "cortex_notification_rule" "critical_alerts" {
  name         = "Critical Alert Notifications"
  description  = "Email SOC team on critical severity alerts"
  forward_type = "Alert"
  enabled      = true
  email_distribution_list = ["soc@example.com"]
  email_aggregation       = 300
}

# --- BIOC Rules ---

resource "cortex_bioc_rule" "suspicious_powershell" {
  name     = "Suspicious PowerShell Execution"
  severity = "SEV_040_HIGH"
  status   = "ENABLED"
  category = "MALWARE"
  comment  = "Detect encoded PowerShell commands"
}

# --- TIM Rules ---

resource "cortex_tim_rule" "threat_feed" {
  name        = "External Threat Feed Detection"
  type        = "DETECTION"
  severity    = "SEV_030_MEDIUM"
  status      = "ENABLED"
  description = "Detect indicators matching external threat feeds"
}

# --- FIM (File Integrity Monitoring) ---

resource "cortex_fim_rule_group" "linux_config" {
  name            = "Linux Configuration Files"
  description     = "Monitor critical Linux configuration files"
  os_type         = "linux"
  monitoring_mode = "real_time"
}

resource "cortex_fim_rule" "etc_passwd" {
  type               = "FILE"
  path               = "/etc/passwd"
  description        = "Monitor password file"
  group_id           = cortex_fim_rule_group.linux_config.group_id
  monitor_all_events = true
}

resource "cortex_fim_rule" "ssh_config" {
  type        = "FILE"
  path        = "/etc/ssh/sshd_config"
  description = "Monitor SSH daemon configuration"
  group_id    = cortex_fim_rule_group.linux_config.group_id
}

# --- Device Control Classes ---

resource "cortex_device_control_class" "usb_storage" {
  type = "USB Mass Storage"
}

# --- Custom Statuses ---

resource "cortex_custom_status" "investigating" {
  pretty_name = "Under Investigation"
  status_type = "status"
  priority    = 10
}

# --- Incident Domains ---

resource "cortex_incident_domain" "cloud_security" {
  pretty_name = "Cloud Security"
  description = "Cloud infrastructure security incidents"
  color       = "#0077B6"
}

# --- Rules Exceptions ---

resource "cortex_rules_exception" "false_positive" {
  name        = "Known False Positive - Internal Scanner"
  description = "Exclude alerts from internal vulnerability scanner"
  alert_id    = "scanner_alert_001"
}

# --- Attack Surface Rules (system-defined, override only) ---

# resource "cortex_attack_surface_rule" "rdp_exposure" {
#   issue_type_id  = "RDP_EXPOSURE"
#   enabled_status = "Enabled"
#   priority       = "High"
# }

# --- Analytics Detectors (system-defined, severity/status override only) ---

# resource "cortex_analytics_detector" "brute_force" {
#   global_rule_id = "analytics_brute_force_001"
#   severity       = "SEV_040_HIGH"
#   status         = "ENABLED"
# }

# ============================================================================
# Phase 2: XSIAM Configuration Resources
# ============================================================================

# --- Data Sources ---

data "cortex_datasets" "all" {}

data "cortex_broker_vms" "all" {}

data "cortex_collector_policies" "all" {}

# --- Parsing Rules (singleton, hash-based optimistic lock) ---

resource "cortex_parsing_rules" "main" {
  text = <<-EOT
    [INGEST:vendor="custom", product="webapp", target_dataset="custom_webapp_logs", no_hit=drop]
    alter _raw_log = to_string(_raw_log)
    | alter src_ip = arrayindex(regextract(_raw_log, "src=(\d+\.\d+\.\d+\.\d+)"), 0)
    | alter action = arrayindex(regextract(_raw_log, "action=(\w+)"), 0);
  EOT
}

# --- Data Modeling Rules (singleton, hash-based optimistic lock) ---

resource "cortex_data_modeling_rules" "main" {
  text = <<-EOT
    [MODEL: dataset="custom_webapp_logs"]
    alter xdm.event.type = "WEB_REQUEST"
    | alter xdm.source.ipv4 = src_ip
    | alter xdm.event.outcome = if(action = "allow", XDM_CONST.OUTCOME_SUCCESS, XDM_CONST.OUTCOME_FAILURE);
  EOT
}

# --- Auto Upgrade Settings (singleton) ---

resource "cortex_auto_upgrade_settings" "main" {
  batch_size = 500
  start_time = "02:00"
  end_time   = "06:00"
  days       = ["Saturday", "Sunday"]
}

# --- Collector Groups ---

resource "cortex_collector_group" "syslog_collectors" {
  name        = "Syslog Collectors"
  description = "Collectors receiving syslog data"
  type        = "STATIC"
}

# --- Collector Distribution ---

resource "cortex_collector_distribution" "linux_latest" {
  name          = "Linux Collector Latest"
  description   = "Latest Linux collector package"
  agent_version = "1.5.1.2048"
  platform      = "AGENT_OS_LINUX"
}

# --- Collector Profile ---

resource "cortex_collector_profile" "custom_linux" {
  name        = "Custom Linux Profile"
  description = "Custom syslog collector profile"
  platform    = "AGENT_OS_LINUX"
  modules     = base64encode(file("${path.module}/collector_modules.yaml"))
}

# --- ASM Asset Removal (irreversible!) ---

# resource "cortex_asm_asset_removal" "decommissioned" {
#   assets = [
#     {
#       asset_type = "Domain"
#       asset_name = "old-app.example.com"
#     },
#     {
#       asset_type = "IP_RANGE"
#       asset_name = "10.99.0.0/16"
#     }
#   ]
# }
