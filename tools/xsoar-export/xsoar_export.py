#!/usr/bin/env python3
"""
xsoar-export: Export XSOAR configuration as Terraform .tf files.

Usage:
    python3 xsoar_export.py --url https://xsoar.example.com --api-key KEY --insecure --output-dir ./exported
    python3 xsoar_export.py --url URL --api-key KEY --auth-id 9 --insecure --output-dir ./exported
    python3 xsoar_export.py --url URL --api-key KEY --resources marketplace,integrations,roles --output-dir ./exported
"""

import argparse
import json
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

logger = logging.getLogger(__name__)

# --- HCL Generation ---

def hcl_string(value: str) -> str:
    """Escape and quote a string for HCL."""
    escaped = value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
    return f'"{escaped}"'


def hcl_value(value: Any, indent: int = 2) -> str:
    """Convert a Python value to HCL representation."""
    if isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, (int, float)):
        return str(value)
    elif isinstance(value, str):
        return hcl_string(value)
    elif isinstance(value, list):
        items = ", ".join(hcl_value(v) for v in value)
        return f"[{items}]"
    elif isinstance(value, dict):
        pad = " " * (indent + 2)
        lines = []
        for k, v in value.items():
            lines.append(f"{pad}{hcl_string(k)} = {hcl_value(v, indent + 2)}")
        return "{\n" + "\n".join(lines) + "\n" + " " * indent + "}"
    elif value is None:
        return "null"
    else:
        return hcl_string(str(value))


def sanitize_tf_id(name: str) -> str:
    """Convert a name to a valid Terraform resource identifier."""
    result = re.sub(r'[^a-zA-Z0-9]', '_', name)
    result = re.sub(r'_+', '_', result)
    result = result.strip('_').lower()
    if result and result[0].isdigit():
        result = '_' + result
    if not result:
        result = '_unnamed'
    return result


def make_unique_ids(names: List[str]) -> Dict[str, str]:
    """Create unique Terraform identifiers from a list of names."""
    result = {}
    seen = {}
    for name in names:
        tf_id = sanitize_tf_id(name)
        if tf_id in seen:
            seen[tf_id] += 1
            tf_id = f"{tf_id}_{seen[tf_id]}"
        else:
            seen[tf_id] = 0
        result[name] = tf_id
    return result


def render_resource(resource_type: str, tf_id: str, attrs: Dict[str, Any],
                    comments: Optional[List[str]] = None) -> str:
    """Render a single HCL resource block."""
    lines = []
    if comments:
        for c in comments:
            lines.append(f"# {c}")
    lines.append(f'resource "{resource_type}" "{tf_id}" {{')
    for key, value in attrs.items():
        if isinstance(value, str) and value.startswith("var."):
            lines.append(f"  {key} = {value}")
        else:
            lines.append(f"  {key} = {hcl_value(value)}")
    lines.append("}")
    return "\n".join(lines)


# --- XSOAR Client ---

class XSOARClient:
    """HTTP client for Cortex XSOAR REST API."""

    def __init__(self, base_url: str, api_key: str, insecure: bool = False,
                 auth_id: str = ""):
        self.base_url = base_url.rstrip("/")
        self.auth_id = auth_id
        self.is_v8 = bool(auth_id)
        # V8 uses /xsoar/ prefix for all API paths
        self.prefix = "/xsoar" if self.is_v8 else ""
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        if auth_id:
            self.session.headers["x-xdr-auth-id"] = auth_id
        self.session.verify = not insecure
        if insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get(self, path: str) -> Any:
        resp = self.session.get(f"{self.base_url}{self.prefix}{path}")
        resp.raise_for_status()
        return resp.json() if resp.content else None

    def post(self, path: str, data: Any = None) -> Any:
        resp = self.session.post(f"{self.base_url}{self.prefix}{path}", json=data or {})
        resp.raise_for_status()
        return resp.json() if resp.content else None


# --- Exporters ---

SENSITIVE_PARAM_TYPES = {9, 14}  # 9=password, 14=encrypted


def export_server_config(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export server configuration as xsoar_server_config resources."""
    try:
        data = client.get("/system/config")
    except Exception as e:
        logger.warning(f"Failed to fetch server config: {e}")
        return "", [], {}

    sys_conf = data.get("sysConf", {}) if isinstance(data, dict) else {}
    blocks = []
    imports = []

    # Skip internal/computed keys
    skip_keys = {"versn", "dbwizard.status", "encryptedDBKey"}

    for key in sorted(sys_conf.keys()):
        if key in skip_keys:
            continue
        val = sys_conf[key]
        if isinstance(val, (dict, list)):
            continue  # Skip complex values
        tf_id = sanitize_tf_id(key)
        block = render_resource("cortex_server_config", tf_id, {
            "key": key,
            "value": str(val),
        }, comments=[f"Server config: {key}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_server_config.{tf_id} "{key}"')

    if not blocks:
        return "", [], {}
    content = "# Server Configuration\n# Generated by xsoar-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_marketplace_packs(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export installed marketplace packs."""
    try:
        packs = client.get("/contentpacks/metadata/installed")
    except Exception as e:
        logger.warning(f"Failed to fetch installed packs: {e}")
        return "", [], {}

    if not isinstance(packs, list):
        return "", [], {}

    blocks = []
    imports = []
    names = [p.get("id", f"pack_{i}") for i, p in enumerate(packs)]
    id_map = make_unique_ids(names)

    for pack in packs:
        pack_id = pack.get("id", "")
        version = pack.get("currentVersion", "")
        name = pack.get("name", pack_id)
        tf_id = id_map.get(pack_id, sanitize_tf_id(pack_id))

        attrs = {"pack_id": pack_id}
        if version:
            attrs["version"] = version

        block = render_resource("cortex_marketplace_pack", tf_id, attrs,
                                comments=[f"Pack: {name} ({pack_id})"])
        blocks.append(block)
        imports.append(f'terraform import cortex_marketplace_pack.{tf_id} "{pack_id}"')

    if not blocks:
        return "", [], {}
    content = "# Marketplace Packs\n# Generated by xsoar-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_integration_instances(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export integration instances."""
    try:
        data = client.post("/settings/integration/search", {"size": 500})
    except Exception as e:
        logger.warning(f"Failed to fetch integrations: {e}")
        return "", [], {}

    instances = data.get("instances", []) if isinstance(data, dict) else []
    if not instances:
        return "", [], {}

    blocks = []
    imports = []
    variables = {}
    names = [inst.get("name", f"inst_{i}") for i, inst in enumerate(instances)]
    id_map = make_unique_ids(names)

    for inst in instances:
        name = inst.get("name", "")
        brand = inst.get("brand", "")
        tf_id = id_map.get(name, sanitize_tf_id(name))
        enabled = inst.get("enabled", "true")

        attrs = {
            "name": name,
            "integration_name": brand,
            "enabled": enabled == "true" or enabled is True,
        }

        # Build config map - data can be None
        config_map = {}
        instance_data = inst.get("data") or []
        sensitive_comments = []

        for param in instance_data:
            if not isinstance(param, dict):
                continue
            param_name = param.get("name", "")
            param_display = param.get("display", param_name)
            param_value = param.get("value", "")
            param_type = param.get("type", 0)
            has_value = param.get("hasvalue", False)

            key = param_display if param_display else param_name
            if not key:
                continue

            if param_type in SENSITIVE_PARAM_TYPES:
                var_name = f"{tf_id}_{sanitize_tf_id(param_name)}"
                variables[var_name] = {
                    "description": f"Sensitive value '{key}' for '{name}'",
                    "sensitive": True,
                }
                config_map[key] = f"REPLACE_WITH_var.{var_name}"
                sensitive_comments.append(f"NOTE: config['{key}'] is sensitive - use var.{var_name}")
            elif has_value and str(param_value):
                config_map[key] = str(param_value)

        if config_map:
            attrs["config"] = config_map

        # Optional fields
        prop_labels = inst.get("propagationLabels")
        if prop_labels and isinstance(prop_labels, list) and len(prop_labels) > 0:
            attrs["propagation_labels"] = prop_labels

        incoming_mapper = inst.get("incomingMapperId", "")
        if incoming_mapper:
            attrs["incoming_mapper_id"] = incoming_mapper

        mapping_id = inst.get("mappingId", "")
        if mapping_id:
            attrs["mapping_id"] = mapping_id

        engine = inst.get("engine", "")
        if engine:
            attrs["engine"] = engine

        engine_group = inst.get("engineGroup", "")
        if engine_group:
            attrs["engine_group"] = engine_group

        comments = [f"Integration: {name} (brand: {brand})"] + sensitive_comments
        block = render_resource("cortex_integration_instance", tf_id, attrs, comments=comments)
        blocks.append(block)
        imports.append(f'terraform import cortex_integration_instance.{tf_id} "{name}"')

    if not blocks:
        return "", [], {}
    content = "# Integration Instances\n# Generated by xsoar-export\n\n" + "\n\n".join(blocks)
    return content, imports, variables


def export_roles(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export roles."""
    try:
        roles = client.get("/roles")
    except Exception as e:
        logger.warning(f"Failed to fetch roles: {e}")
        return "", [], {}

    if not isinstance(roles, list):
        return "", [], {}

    blocks = []
    imports = []
    names = [r.get("name", f"role_{i}") for i, r in enumerate(roles)]
    id_map = make_unique_ids(names)

    for role in roles:
        name = role.get("name", "")
        tf_id = id_map.get(name, sanitize_tf_id(name))
        permissions = role.get("permissions", {})

        attrs = {
            "name": name,
            "permissions": json.dumps(permissions),
        }

        block = render_resource("cortex_role", tf_id, attrs, comments=[f"Role: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_role.{tf_id} "{name}"')

    if not blocks:
        return "", [], {}
    content = "# Roles\n# Generated by xsoar-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_api_keys(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export API keys (read-only, key values not available)."""
    try:
        keys = client.get("/apikeys")
    except Exception as e:
        logger.warning(f"Failed to fetch API keys: {e}")
        return "", [], {}

    if not isinstance(keys, list):
        return "", [], {}

    blocks = []
    imports = []
    names = [k.get("name", f"key_{i}") for i, k in enumerate(keys)]
    id_map = make_unique_ids(names)

    for key in keys:
        name = key.get("name", "")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {"name": name}
        block = render_resource("cortex_api_key", tf_id, attrs,
                                comments=[f"API Key: {name}", "NOTE: Key value is not exported (sensitive)"])
        blocks.append(block)
        imports.append(f'terraform import cortex_api_key.{tf_id} "{name}"')

    if not blocks:
        return "", [], {}
    content = "# API Keys\n# Generated by xsoar-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_jobs(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export jobs."""
    try:
        data = client.post("/jobs/search", {"page": 0, "size": 500})
    except Exception as e:
        logger.warning(f"Failed to fetch jobs: {e}")
        return "", [], {}

    # data can be None or {"total": 0, "data": null}
    jobs = []
    if isinstance(data, dict):
        jobs = data.get("data") or []
    if not jobs:
        return "", [], {}

    blocks = []
    imports = []
    names = [j.get("name", f"job_{i}") for i, j in enumerate(jobs)]
    id_map = make_unique_ids(names)

    for job in jobs:
        name = job.get("name", "")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "playbook_id": job.get("playbookId", ""),
        }
        if job.get("scheduled"):
            attrs["scheduled"] = True
        if job.get("cron"):
            attrs["cron"] = job["cron"]
        if job.get("recurrent"):
            attrs["recurrent"] = True
        if job.get("shouldTriggerNew"):
            attrs["should_trigger_new"] = True
        tags = job.get("tags") or []
        if tags:
            attrs["tags"] = tags

        block = render_resource("cortex_job", tf_id, attrs, comments=[f"Job: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_job.{tf_id} "{name}"')

    if not blocks:
        return "", [], {}
    content = "# Jobs\n# Generated by xsoar-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_preprocessing_rules(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export pre-processing rules."""
    try:
        rules = client.get("/preprocess/rules")
    except Exception as e:
        logger.warning(f"Failed to fetch preprocessing rules: {e}")
        return "", [], {}

    if not isinstance(rules, list):
        return "", [], {}

    blocks = []
    imports = []
    names = [r.get("name", f"rule_{i}") for i, r in enumerate(rules)]
    id_map = make_unique_ids(names)

    for rule in rules:
        name = rule.get("name", "")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        filters = {}
        if rule.get("newEventFilters"):
            filters["newEventFilters"] = rule["newEventFilters"]
        if rule.get("existingEventsFilters"):
            filters["existingEventsFilters"] = rule["existingEventsFilters"]

        attrs = {
            "name": name,
            "enabled": rule.get("enabled", True),
            "action": rule.get("action", ""),
            "rules_json": json.dumps(filters),
        }
        if rule.get("scriptName"):
            attrs["script_name"] = rule["scriptName"]

        block = render_resource("cortex_preprocessing_rule", tf_id, attrs,
                                comments=[f"Preprocessing Rule: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_preprocessing_rule.{tf_id} "{name}"')

    if not blocks:
        return "", [], {}
    content = "# Pre-processing Rules\n# Generated by xsoar-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_password_policy(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export password policy (singleton)."""
    try:
        policy = client.get("/settings/password-policy")
    except Exception as e:
        logger.warning(f"Failed to fetch password policy: {e}")
        return "", [], {}

    if not isinstance(policy, dict):
        return "", [], {}

    attrs = {}
    # Map API field names to the actual Terraform resource fields
    # The password_policy resource uses these field names from the API struct:
    field_map = {
        "minPasswordLength": "min_password_length",
        "minLowercaseChars": "min_lowercase_chars",
        "minUppercaseChars": "min_uppercase_chars",
        "minDigitsOrSymbols": "min_digits_or_symbols",
        "maxFailedLoginAttempts": "max_failed_login_attempts",
        "selfUnlockAfterMinutes": "self_unlock_after_minutes",
        "expireAfter": "expire_after",
    }
    bool_fields = {
        "enabled": "enabled",
        "preventRepetition": "prevent_repetition",
    }

    for api_key, tf_key in field_map.items():
        if api_key in policy:
            attrs[tf_key] = int(policy[api_key])

    for api_key, tf_key in bool_fields.items():
        if api_key in policy:
            attrs[tf_key] = bool(policy[api_key])

    block = render_resource("cortex_password_policy", "main", attrs,
                            comments=["Password Policy (singleton)"])
    content = "# Password Policy\n# Generated by xsoar-export\n\n" + block
    imports = ['terraform import cortex_password_policy.main "password_policy"']
    return content, imports, {}


def export_credentials(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export credentials (passwords are not exported)."""
    try:
        resp = client.post("/settings/credentials", {})
    except Exception as e:
        logger.warning(f"Failed to fetch credentials: {e}")
        return "", [], {}

    # Response format: {"credentials": [...], "total": N} or just a list
    creds = []
    if isinstance(resp, dict):
        creds = resp.get("credentials") or []
    elif isinstance(resp, list):
        creds = resp

    if not creds:
        return "", [], {}

    blocks = []
    imports = []
    variables = {}
    names = [c.get("name", f"cred_{i}") for i, c in enumerate(creds)]
    id_map = make_unique_ids(names)

    for cred in creds:
        name = cred.get("name", "")
        tf_id = id_map.get(name, sanitize_tf_id(name))
        var_name = f"{tf_id}_password"

        variables[var_name] = {
            "description": f"Password for credential '{name}'",
            "sensitive": True,
        }

        attrs = {
            "name": name,
            "user": cred.get("user", ""),
            "password": f"var.{var_name}",
        }
        if cred.get("comment"):
            attrs["comment"] = cred["comment"]

        block = render_resource("cortex_credential", tf_id, attrs,
                                comments=[f"Credential: {name}", "NOTE: Password must be provided via variable"])
        blocks.append(block)
        imports.append(f'terraform import cortex_credential.{tf_id} "{name}"')

    if not blocks:
        return "", [], {}
    content = "# Credentials\n# Generated by xsoar-export\n\n" + "\n\n".join(blocks)
    return content, imports, variables


def export_exclusion_list(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export indicator exclusion list entries."""
    try:
        entries = client.get("/indicators/whitelisted")
    except Exception as e:
        logger.warning(f"Failed to fetch exclusion list: {e}")
        return "", [], {}

    if not isinstance(entries, list) or not entries:
        return "", [], {}

    blocks = []
    imports = []
    names = [e.get("value", f"excl_{i}") for i, e in enumerate(entries)]
    id_map = make_unique_ids(names)

    for entry in entries:
        value = entry.get("value", "")
        entry_type = entry.get("type", "standard")
        reason = entry.get("reason", "")
        entry_id = entry.get("id", value)
        tf_id = id_map.get(value, sanitize_tf_id(value))

        attrs = {
            "value": value,
            "type": entry_type,
        }
        if reason:
            attrs["reason"] = reason

        block = render_resource("cortex_exclusion_list", tf_id, attrs,
                                comments=[f"Exclusion: {value} ({entry_type})"])
        blocks.append(block)
        imports.append(f'terraform import cortex_exclusion_list.{tf_id} "{entry_id}"')

    if not blocks:
        return "", [], {}
    content = "# Indicator Exclusion List\n# Generated by xsoar-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


# --- Orchestrator ---

EXPORTERS = {
    "server_config": ("server_config.tf", export_server_config),
    "marketplace": ("marketplace_packs.tf", export_marketplace_packs),
    "integrations": ("integration_instances.tf", export_integration_instances),
    "roles": ("roles.tf", export_roles),
    "api_keys": ("api_keys.tf", export_api_keys),
    "jobs": ("jobs.tf", export_jobs),
    "preprocessing_rules": ("preprocessing_rules.tf", export_preprocessing_rules),
    "password_policy": ("password_policy.tf", export_password_policy),
    "credentials": ("credentials.tf", export_credentials),
    "exclusion_list": ("exclusion_list.tf", export_exclusion_list),
}


def write_main_tf(output_dir: str, auth_id: str):
    """Write the main.tf provider configuration."""
    auth_id_line = ""
    if auth_id:
        auth_id_line = '  auth_id  = var.xsoar_auth_id\n'

    content = f'''# Generated by xsoar-export
terraform {{
  required_providers {{
    cortex = {{
      source  = "mdrobniu/cortex"
      version = "0.1.0"
    }}
  }}
}}

provider "cortex" {{
  base_url = var.xsoar_url
  api_key  = var.xsoar_api_key
{auth_id_line}  insecure = var.xsoar_insecure
}}
'''
    with open(os.path.join(output_dir, "main.tf"), "w") as f:
        f.write(content)


def write_variables_tf(output_dir: str, variables: Dict[str, Dict], auth_id: str):
    """Write the variables.tf file."""
    lines = [
        "# Variables for XSOAR Terraform configuration",
        "# Generated by xsoar-export",
        "",
        'variable "xsoar_url" {',
        '  description = "XSOAR base URL"',
        "  type        = string",
        "}",
        "",
        'variable "cortex_api_key" {',
        '  description = "XSOAR API key"',
        "  type        = string",
        "  sensitive   = true",
        "}",
        "",
    ]

    if auth_id:
        lines.extend([
            'variable "xsoar_auth_id" {',
            '  description = "XSOAR 8 auth ID"',
            "  type        = string",
            f'  default     = "{auth_id}"',
            "}",
            "",
        ])

    lines.extend([
        'variable "xsoar_insecure" {',
        '  description = "Skip TLS verification"',
        "  type        = bool",
        "  default     = true",
        "}",
        "",
    ])

    for var_name, var_info in sorted(variables.items()):
        lines.append(f'variable "{var_name}" {{')
        lines.append(f'  description = {hcl_string(var_info["description"])}')
        lines.append("  type        = string")
        if var_info.get("sensitive"):
            lines.append("  sensitive   = true")
        lines.append("}")
        lines.append("")

    with open(os.path.join(output_dir, "variables.tf"), "w") as f:
        f.write("\n".join(lines))


def write_tfvars_example(output_dir: str, variables: Dict[str, Dict],
                         url: str, auth_id: str):
    """Write terraform.tfvars.example."""
    lines = [
        "# Example variable values - copy to terraform.tfvars and fill in",
        "# Generated by xsoar-export",
        "",
        f'xsoar_url      = "{url}"',
        'xsoar_api_key  = "YOUR_API_KEY_HERE"',
    ]
    if auth_id:
        lines.append(f'xsoar_auth_id  = "{auth_id}"')
    lines.extend([
        "xsoar_insecure = true",
        "",
    ])
    for var_name in sorted(variables.keys()):
        lines.append(f'{var_name} = ""  # TODO: Fill in')

    with open(os.path.join(output_dir, "terraform.tfvars.example"), "w") as f:
        f.write("\n".join(lines))


def write_import_sh(output_dir: str, all_imports: List[str]):
    """Write import.sh script."""
    lines = [
        "#!/bin/bash",
        "# Terraform import commands for XSOAR resources",
        "# Generated by xsoar-export",
        "#",
        "# Usage: bash import.sh",
        "# Note: Run 'terraform init' first",
        "",
        "set -e",
        "",
    ]
    lines.extend(all_imports)

    filepath = os.path.join(output_dir, "import.sh")
    with open(filepath, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(filepath, 0o755)


def run_export(client: XSOARClient, output_dir: str, resource_types: Optional[List[str]],
               save_raw: bool, url: str, auth_id: str):
    """Run the full export pipeline."""
    os.makedirs(output_dir, exist_ok=True)

    if save_raw:
        os.makedirs(os.path.join(output_dir, "raw"), exist_ok=True)

    all_imports = []
    all_variables = {}

    # Determine which exporters to run
    if resource_types is None:
        exporters_to_run = EXPORTERS
    else:
        exporters_to_run = {k: v for k, v in EXPORTERS.items() if k in resource_types}

    for key, (filename, exporter_fn) in exporters_to_run.items():
        print(f"  Exporting {key}...")
        try:
            content, imports, variables = exporter_fn(client)
        except Exception as e:
            print(f"    ERROR: {e}")
            logger.warning(f"Error exporting {key}: {e}", exc_info=True)
            continue

        if content:
            filepath = os.path.join(output_dir, filename)
            with open(filepath, "w") as f:
                f.write(content + "\n")
            print(f"    -> {filepath} ({content.count('resource ')} resources)")
        else:
            print(f"    (no resources found)")

        all_imports.extend(imports)
        all_variables.update(variables)

    # Write orchestration files
    write_main_tf(output_dir, auth_id)
    write_variables_tf(output_dir, all_variables, auth_id)
    write_tfvars_example(output_dir, all_variables, url, auth_id)
    write_import_sh(output_dir, all_imports)

    print(f"\nExport complete!")
    print(f"  Output directory: {output_dir}")
    print(f"  Total import commands: {len(all_imports)}")
    print(f"  Variables to configure: {len(all_variables)}")
    print(f"\nNext steps:")
    print(f"  1. cd {output_dir}")
    print(f"  2. cp terraform.tfvars.example terraform.tfvars")
    print(f"  3. Edit terraform.tfvars with actual values")
    print(f"  4. terraform init")
    print(f"  5. bash import.sh")
    print(f"  6. terraform plan")


def main():
    parser = argparse.ArgumentParser(
        prog="xsoar-export",
        description="Export XSOAR configuration as Terraform .tf files"
    )
    parser.add_argument("--url", default=os.environ.get("DEMISTO_BASE_URL"),
                        help="XSOAR base URL (or DEMISTO_BASE_URL env var)")
    parser.add_argument("--api-key", default=os.environ.get("DEMISTO_API_KEY"),
                        help="XSOAR API key (or DEMISTO_API_KEY env var)")
    parser.add_argument("--auth-id", default=os.environ.get("DEMISTO_AUTH_ID", ""),
                        help="XSOAR 8 auth ID (or DEMISTO_AUTH_ID env var)")
    parser.add_argument("--insecure", action="store_true",
                        default=bool(os.environ.get("DEMISTO_INSECURE")),
                        help="Skip TLS certificate verification")
    parser.add_argument("--output-dir", "-o", default="./xsoar-terraform",
                        help="Output directory (default: ./xsoar-terraform)")
    parser.add_argument("--resources", "-r", default="all",
                        help=f"Comma-separated resource types to export (default: all). "
                             f"Available: {', '.join(EXPORTERS.keys())}")
    parser.add_argument("--save-raw", action="store_true",
                        help="Save raw API JSON responses")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")

    args = parser.parse_args()

    if not args.url:
        parser.error("--url is required (or set DEMISTO_BASE_URL)")
    if not args.api_key:
        parser.error("--api-key is required (or set DEMISTO_API_KEY)")

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    resource_types = None if args.resources == "all" else [r.strip() for r in args.resources.split(",")]

    client = XSOARClient(
        base_url=args.url,
        api_key=args.api_key,
        insecure=args.insecure,
        auth_id=args.auth_id,
    )

    # Test connection - use /about (no prefix needed for V6, V8 prefix added by client)
    print(f"Connecting to {args.url}...")
    try:
        about = client.get("/about")
        version = "unknown"
        if isinstance(about, dict):
            version = about.get("demistoVersion", about.get("version", "unknown"))
        print(f"  Connected to XSOAR {version}")
    except Exception as e:
        print(f"  ERROR: Could not connect: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\nExporting configuration...")
    run_export(client, args.output_dir, resource_types, args.save_raw, args.url, args.auth_id)


if __name__ == "__main__":
    main()
