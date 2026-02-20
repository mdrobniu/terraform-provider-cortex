terraform {
  required_providers {
    cortex = {
      source  = "registry.terraform.io/mdrobniu/cortex"
      version = "~> 0.2"
    }
  }
}

# Configure the Cortex provider
# Values can also be set via environment variables:
#   DEMISTO_BASE_URL, DEMISTO_API_KEY, DEMISTO_INSECURE, DEMISTO_AUTH_ID
provider "cortex" {
  base_url = var.xsoar_url
  api_key  = var.xsoar_api_key
  insecure = true

  # For XSOAR 8 / XSIAM, also set:
  # auth_id = var.xsoar_auth_id

  # For XSOAR 8 OPP webapp resources (external_storage, backup_schedule, security_settings):
  # ui_url   = var.xsoar_ui_url
  # username = var.xsoar_username
  # password = var.xsoar_password

  # For XSIAM / XSOAR 8 SaaS webapp resources:
  # session_token = var.session_token
}

variable "xsoar_url" {
  description = "XSOAR/XSIAM API base URL"
  type        = string
  default     = "https://xsoar.example.com"
}

variable "xsoar_api_key" {
  description = "XSOAR/XSIAM API key"
  type        = string
  sensitive   = true
}

variable "xsoar_auth_id" {
  description = "XSOAR 8 / XSIAM auth ID (required for V8/XSIAM)"
  type        = string
  default     = ""
}

variable "xsoar_ui_url" {
  description = "XSOAR 8 OPP UI URL (for webapp session auth)"
  type        = string
  default     = ""
}

variable "xsoar_username" {
  description = "XSOAR 8 OPP username (for webapp session auth)"
  type        = string
  default     = ""
}

variable "xsoar_password" {
  description = "XSOAR 8 OPP password (for webapp session auth)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "session_token" {
  description = "Session token for XSIAM/SaaS webapp API access"
  type        = string
  sensitive   = true
  default     = ""
}
