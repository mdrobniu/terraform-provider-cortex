# Changelog

## 0.2.0

### XSIAM Webapp Resources (16 new resources)
- Added 16 XSIAM-specific resources using webapp session authentication:
  - `cortex_correlation_rule` - XSIAM correlation rules
  - `cortex_ioc_rule` - XSIAM IOC rules (no update API, uses delete+recreate)
  - `cortex_edl` - External Dynamic List configuration (singleton)
  - `cortex_vulnerability_scan_settings` - Vulnerability scan engine settings (singleton)
  - `cortex_agent_group` - Endpoint agent groups
  - `cortex_notification_rule` - Alert notification/forwarding rules
  - `cortex_bioc_rule` - Behavioral Indicator of Compromise rules
  - `cortex_tim_rule` - Threat Intelligence Management rules
  - `cortex_fim_rule_group` - File Integrity Monitoring rule groups
  - `cortex_fim_rule` - File Integrity Monitoring rules
  - `cortex_analytics_detector` - Analytics detector overrides (system-defined, severity/status only)
  - `cortex_attack_surface_rule` - Attack surface rule overrides (system-defined, enabled/priority only)
  - `cortex_device_control_class` - USB device control classes
  - `cortex_custom_status` - Custom alert/incident statuses
  - `cortex_incident_domain` - Incident domain categories
  - `cortex_rules_exception` - Detection rule exceptions (no update API, uses delete+recreate)

### XSIAM Configuration Resources (7 new resources)
- Added 7 XSIAM configuration resources:
  - `cortex_parsing_rules` - XQL parsing rules (singleton, hash-based optimistic lock)
  - `cortex_data_modeling_rules` - XQL data modeling rules (singleton, hash-based optimistic lock)
  - `cortex_auto_upgrade_settings` - Collector auto-upgrade global settings (singleton)
  - `cortex_collector_group` - XDR collector groups (no update API, RequiresReplace)
  - `cortex_collector_distribution` - XDR collector distribution packages (create+delete)
  - `cortex_collector_profile` - XDR collector profiles (create-only, state-only delete)
  - `cortex_asm_asset_removal` - Bulk ASM asset removal (irreversible, fire-and-forget)

### Data Sources (3 new)
- Added 3 XSIAM-only data sources:
  - `data.cortex_datasets` - List all XSIAM datasets
  - `data.cortex_broker_vms` - List broker VM devices
  - `data.cortex_collector_policies` - List collector policies

### cortex-login CLI Tool
- New `tools/cortex-login/` tool automates browser-based SSO login for session token capture
- Saves session to `~/.cortex/session.json` for automatic provider authentication
- Provider auto-loads session file when no `session_token` is configured

### Documentation
- Added documentation for all 23 XSIAM webapp resources
- Added documentation for 3 data sources
- Updated provider index docs with full webapp resource list
- Updated examples with XSIAM configuration patterns
- Updated README with complete resource compatibility matrix

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
