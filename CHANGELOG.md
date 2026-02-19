# Changelog

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
