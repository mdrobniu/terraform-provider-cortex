---
page_title: "cortex_password_policy Resource - cortex"
subcategory: ""
description: |-
  Manages the password policy for the XSOAR instance.
---

# cortex_password_policy (Resource)

Manages the password policy for the XSOAR instance.

This is a **singleton resource** -- only one password policy exists per XSOAR instance. It controls password complexity requirements, expiration, and account lockout behavior.

~> **Note:** Since this is a singleton resource, only one `cortex_password_policy` resource should be defined per Terraform configuration. Destroying this resource resets the password policy to default values rather than deleting it.

## Example Usage

### Enforce a strict password policy

```terraform
resource "cortex_password_policy" "main" {
  enabled                  = true
  min_password_length      = 14
  min_lowercase_chars      = 2
  min_uppercase_chars      = 2
  min_digits_or_symbols    = 2
  prevent_repetition       = true
  expire_after             = 90
  max_failed_login_attempts = 5
  self_unlock_after_minutes = 30
}
```

### Minimal password policy

```terraform
resource "cortex_password_policy" "main" {
  enabled             = true
  min_password_length = 8
}
```

## Schema

### Optional

- `enabled` (Boolean) Whether the password policy is enforced.
- `min_password_length` (Number) The minimum required password length.
- `min_lowercase_chars` (Number) The minimum number of lowercase characters required.
- `min_uppercase_chars` (Number) The minimum number of uppercase characters required.
- `min_digits_or_symbols` (Number) The minimum number of digits or special characters required.
- `prevent_repetition` (Boolean) Whether to prevent password reuse.
- `expire_after` (Number) The number of days after which passwords expire. Set to `0` to disable expiration.
- `max_failed_login_attempts` (Number) The maximum number of failed login attempts before the account is locked.
- `self_unlock_after_minutes` (Number) The number of minutes after which a locked account is automatically unlocked. Set to `0` to require manual unlock.

### Read-Only

- `id` (String) The identifier of the password policy. Always `"password_policy"`.

## Import

Import is supported using the fixed identifier `password_policy`:

```shell
terraform import cortex_password_policy.main "password_policy"
```
