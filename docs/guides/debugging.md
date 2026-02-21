---
page_title: "Debugging and Troubleshooting"
subcategory: "Guides"
description: |-
  How to enable debug logging, diagnose issues, and report bugs for the Cortex provider.
---

# Debugging and Troubleshooting

## Enable Debug Logging

The provider uses Terraform's built-in logging framework. Set the `TF_LOG` environment variable to control log verbosity:

```bash
# Show provider debug logs (API requests, response codes, version detection)
TF_LOG=DEBUG terraform plan

# Show full trace logs including request/response bodies
TF_LOG=TRACE terraform plan

# Write logs to a file
TF_LOG=TRACE TF_LOG_PATH=./terraform-debug.log terraform plan

# Filter to provider logs only (excludes Terraform core)
TF_LOG_PROVIDER=TRACE TF_LOG_PATH=./provider-debug.log terraform plan
```

## Log Levels

| Level   | What it shows                                                          |
|---------|------------------------------------------------------------------------|
| `ERROR` | API errors (4xx/5xx), redirect errors, exhausted retries               |
| `WARN`  | Retryable failures (5xx), version detection fallbacks, missing tokens  |
| `INFO`  | XSOAR version detected, deployment mode, session auth status           |
| `DEBUG` | Every API request (method, path, attempt number, status code, body size) |
| `TRACE` | Full request and response bodies (truncated at 2KB/4KB respectively)   |

## Common Errors

### "Version Detection Failed"

The provider could not reach `/about` or `/xsoar/about`. Check:
- `base_url` is correct and the XSOAR instance is reachable
- For XSOAR 8, use the **API URL** (e.g., `https://api-xsoar8.example.com`), not the UI URL
- Network/firewall allows the connection

### "Webapp Session Auth Failed"

The provider could not log in via the UI URL. Check:
- `ui_url`, `username`, and `password` are correct
- The user account has appropriate permissions
- Only affects `cortex_external_storage`, `cortex_backup_schedule`, and `cortex_security_settings`

### HTTP 400 with "errOptimisticLock"

A concurrent modification changed the resource version between read and update. Run `terraform refresh` then retry.

### HTTP 401 Unauthorized

- Verify your `api_key` is valid
- For XSOAR 8, verify `auth_id` is set and correct
- Check the API key has not expired or been revoked

### HTTP 405 Method Not Allowed

The resource operation is not available on this XSOAR version/deployment:
- Roles are read-only on XSOAR 8 (managed at XDR platform level)
- API keys and preprocessing rules are not available on XSOAR 8 SaaS
- HA groups, hosts, accounts, and backup config are XSOAR 6 only

### HTTP 303 Redirect

XSOAR returns 303 to signal that a resource or endpoint is not available. The provider treats this as an error. This usually means the endpoint does not exist on your XSOAR version.

### Webapp Resources: "webapp session required" or "XSIAM webapp session required"

The resource requires a session token for webapp API access. Solutions:

1. **Use `cortex-login`**: Run `cortex-login --url https://mytenant.xdr.us.paloaltonetworks.com` to authenticate and save session cookies to `~/.cortex/session.json`. The provider loads this file automatically.
2. **Set `session_token`**: Copy the session cookie from browser DevTools and set it in the provider config or via `CORTEX_SESSION_TOKEN`.
3. **For XSOAR 8 OPP**: Use `ui_url`, `username`, and `password` instead of `session_token`.

### Webapp Resources: HTTP 403 or "Session expired"

The session token has expired. Session tokens typically last 8 hours. Re-run `cortex-login` or obtain a fresh token from browser DevTools.

### Webapp Resources: Unexpected API Errors After XSIAM Upgrade

The 16 XSIAM webapp resources use internal webapp API endpoints that were developed against **XSIAM V3.4**. These endpoints are not part of the official public API and may change between XSIAM versions. If webapp resources stop working after an upgrade:

1. Enable trace logging: `TF_LOG=TRACE terraform plan`
2. Check the API endpoint path and response in the logs
3. The endpoint may have moved or the request/response format may have changed
4. File an issue with the full trace log (redact sensitive data)

## Reporting Issues

When reporting an issue, include:

1. **Provider version** (`terraform version`)
2. **XSOAR version and deployment mode** (from `GET /about` or `GET /xsoar/about`)
3. **Terraform configuration** (sanitize credentials)
4. **Full debug log** (`TF_LOG_PROVIDER=TRACE TF_LOG_PATH=./debug.log terraform apply`)
5. **Error message** from terraform output
6. **Expected vs actual behavior**

~> **Note:** Trace logs may contain sensitive data. Review and redact `Authorization` headers and credential values before sharing.

File issues at: [github.com/mdrobniu/terraform-provider-cortex/issues](https://github.com/mdrobniu/terraform-provider-cortex/issues)
