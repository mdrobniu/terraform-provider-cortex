---
page_title: "cortex_incident_domain Resource - cortex"
subcategory: ""
description: |-
  Manages incident domains in XSIAM.
---

# cortex_incident_domain (Resource)

Manages incident domains in XSIAM. Incident domains partition incidents into logical groupings with their own status workflows, enabling multi-tenant or multi-department incident management within a single XSIAM tenant.

Each domain has a user-friendly `pretty_name`, a system-generated `name` (derived from the pretty name), and an optional set of custom statuses and resolved statuses that define the incident lifecycle within that domain.

~> **Note:** This resource is only available on XSIAM and requires webapp session authentication (`session_token` or `cortex-login`). Webapp API endpoints are based on XSIAM V3.4 and may differ on other versions.

## Example Usage

```terraform
resource "cortex_incident_domain" "soc" {
  pretty_name = "SOC Operations"
  color       = "#3498db"
  description = "Security Operations Center incidents"

  statuses          = ["New", "In Progress", "Pending Review"]
  resolved_statuses = ["Resolved", "False Positive"]
}

resource "cortex_incident_domain" "it_ops" {
  pretty_name = "IT Operations"
  color       = "#2ecc71"
  description = "IT infrastructure incidents"
}
```

## Argument Reference

* `pretty_name` - (Required) The display name of the incident domain.
* `color` - (Optional) The hex color code for the domain, used in the XSIAM UI (e.g., `#3498db`).
* `description` - (Optional) A description of the incident domain.
* `statuses` - (Optional) A list of status names available within this domain. These define the active states of the incident lifecycle.
* `resolved_statuses` - (Optional) A list of resolved status names within this domain. These define the terminal/closed states of the incident lifecycle.

## Attributes Reference

* `domain_id` - The unique identifier assigned to the incident domain by XSIAM.
* `name` - The system-generated internal name, derived from the pretty name.
* `is_default` - Whether this domain is the default incident domain.

## Import

Incident domains can be imported using their domain ID:

```shell
terraform import cortex_incident_domain.soc 42
```
