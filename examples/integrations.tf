# Configure integration instances
resource "cortex_integration_instance" "virustotal" {
  name             = "VirusTotal"
  integration_name = "VirusTotal"
  enabled          = true

  config = {
    "API Key"  = var.virustotal_api_key
    "useproxy" = "false"
  }
}

resource "cortex_integration_instance" "servicenow" {
  name             = "ServiceNow-Prod"
  integration_name = "ServiceNow v2"
  enabled          = true

  config = {
    "url"      = "https://myinstance.service-now.com"
    "Username" = var.servicenow_username
    "Password" = var.servicenow_password
    "useproxy" = "false"
  }

  incoming_mapper_id = "ServiceNow-incoming-mapper"
  mapping_id         = "ServiceNow-classifier"
}

variable "virustotal_api_key" {
  description = "VirusTotal API key"
  type        = string
  sensitive   = true
}

variable "servicenow_username" {
  description = "ServiceNow username"
  type        = string
}

variable "servicenow_password" {
  description = "ServiceNow password"
  type        = string
  sensitive   = true
}
