# Changelog

## 0.1.2

### XSIAM Support
- Added XSIAM deployment detection via `productMode` from `/about` endpoint
- XSIAM uses the V8 API backend with the same `/xsoar/` prefix endpoints
- Existing resources that work on XSIAM: credential, job, exclusion_list, password_policy, marketplace_pack, integration_instance, role (read-only), list
- `cortex_server_config` returns a clear error on XSIAM (blocked for public API requests)

### New Resource: `cortex_list`
- Manages lists (IP lists, CSV tables, JSON config, markdown docs) across all platforms
- Supports content types: plain_text, json, html, markdown, css
- Works on XSOAR 6, XSOAR 8 OPP, XSOAR 8 SaaS, and XSIAM

### Job Resource Enhancements
- Added `human_cron` nested attribute for XSIAM scheduling (required on XSIAM, optional on XSOAR)
- Added `start_date`, `ending_date`, and `ending_type` attributes
- `human_cron` supports `time_period_type` (minutes/hours/days/weeks/months), `time_period`, and `days`

### Provider Configuration
- Added `session_token` attribute for webapp API access on XSIAM and XSOAR 8 SaaS
- Environment variable: `CORTEX_SESSION_TOKEN`
- Updated provider description to include XSIAM

## 0.1.1

- Added provider documentation for Terraform Registry
- Added resource documentation for all 17 resources
- Added debugging and troubleshooting guide
- Added debug/trace logging for API requests and responses

## 0.1.0

- Initial release
- Support for XSOAR 6, XSOAR 8 OPP, and XSOAR 8 SaaS
- 17 resources: server_config, password_policy, credential, job, exclusion_list, role, api_key, preprocessing_rule, integration_instance, marketplace_pack, account, host, ha_group, backup_config, external_storage, backup_schedule, security_settings
- Automatic version detection and API path routing
- Session-based authentication for OPP webapp endpoints
- Retry logic with exponential backoff for transient failures
