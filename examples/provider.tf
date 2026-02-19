terraform {
  required_providers {
    cortex = {
      source  = "registry.terraform.io/mdrobniu/cortex"
      version = "~> 0.1"
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

  # For XSOAR 8, also set:
  # auth_id = var.xsoar_auth_id
}

variable "xsoar_url" {
  description = "XSOAR base URL"
  type        = string
  default     = "https://xsoar.example.com"
}

variable "xsoar_api_key" {
  description = "XSOAR API key"
  type        = string
  sensitive   = true
}

variable "xsoar_auth_id" {
  description = "XSOAR 8 auth ID (optional)"
  type        = string
  default     = ""
}
