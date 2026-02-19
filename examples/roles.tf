# Manage roles
resource "cortex_role" "analyst" {
  name        = "Analyst"
  permissions = jsonencode({
    "demisto" = ["incidents", "playbooks", "dashboards"]
  })
}

resource "cortex_role" "admin" {
  name        = "CustomAdmin"
  permissions = jsonencode({
    "demisto" = ["adminPage", "incidents", "playbooks", "scripts", "integrations"]
  })
}

# Manage API keys
resource "cortex_api_key" "ci_cd" {
  name = "CI/CD Pipeline Key"
}

output "ci_cd_api_key" {
  value     = cortex_api_key.ci_cd.key_value
  sensitive = true
}
