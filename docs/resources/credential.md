---
page_title: "cortex_credential Resource - terraform-provider-cortex"
subcategory: ""
description: |-
  Manages a stored credential in Cortex XSOAR. Credentials are used by integrations to authenticate with external services.
---

# cortex_credential (Resource)

Manages a stored credential in Cortex XSOAR. Credentials are used by integrations to authenticate with external services.

Supported on XSOAR 6, XSOAR 8 OPP, and XSOAR 8 SaaS.

~> **Note:** The `password` attribute is write-only. The API does not return the password on read, so Terraform cannot detect drift on this field. If the password is changed outside of Terraform, you must taint the resource or update the configuration to trigger a replacement.

## Example Usage

```terraform
resource "cortex_credential" "service_account" {
  name     = "my-svc"
  user     = "svc_user"
  password = var.svc_password
  comment  = "Service account for CI/CD pipeline"
}
```

### Using with an Integration Instance

```terraform
variable "svc_password" {
  type      = string
  sensitive = true
}

resource "cortex_credential" "api_cred" {
  name     = "api-credential"
  user     = "api_user"
  password = var.svc_password
}

resource "cortex_integration_instance" "example" {
  name           = "my-integration"
  integration_id = "SomeIntegration"

  config = {
    credentials = cortex_credential.api_cred.name
  }
}
```

## Schema

### Required

- `name` (String) The unique name of the credential. Used as the identifier in integration configurations.
- `user` (String) The username for the credential.
- `password` (String, Sensitive) The password for the credential. This value is write-only and is not returned by the API on read operations.

### Optional

- `comment` (String) An optional comment or description for the credential.

### Read-Only

- `id` (String) The identifier of the credential. Same as `name`.
- `version` (Number) The current version of the credential. Incremented on each update by the server.

## Import

Credentials can be imported using the credential name:

```shell
terraform import cortex_credential.service_account my-svc
```

~> **Note:** The `password` field cannot be populated during import since the API does not return it. After import, you must set the `password` in your configuration. The next `terraform apply` will update the password.
