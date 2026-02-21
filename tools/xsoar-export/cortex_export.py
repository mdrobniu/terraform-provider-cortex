#!/usr/bin/env python3
"""
cortex-export: Export Cortex XSOAR/XSIAM configuration as Terraform .tf files.

Usage:
    python3 cortex_export.py --url https://xsoar.example.com --api-key KEY --insecure --output-dir ./exported
    python3 cortex_export.py --url URL --api-key KEY --auth-id 9 --insecure --output-dir ./exported
    python3 cortex_export.py --url URL --api-key KEY --auth-id 413 --session-token TOKEN --output-dir ./exported
    python3 cortex_export.py --url URL --api-key KEY --resources marketplace,credentials --output-dir ./exported
"""

import argparse
import json
import logging
import os
import re
import secrets
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
import urllib3

logger = logging.getLogger(__name__)

# --- Platform Detection ---

PLATFORM_V6 = "v6"
PLATFORM_V8_OPP = "v8_opp"
PLATFORM_V8_SAAS = "v8_saas"
PLATFORM_XSIAM = "xsiam"


class PlatformInfo:
    """Detected platform information from /about endpoint."""

    def __init__(self, version: str = "unknown", major: int = 6,
                 product_mode: str = "xsoar", deployment_mode: str = "opp"):
        self.version = version
        self.major = major
        self.product_mode = product_mode
        self.deployment_mode = deployment_mode

    @property
    def platform(self) -> str:
        if self.product_mode == "xsiam":
            return PLATFORM_XSIAM
        if self.major >= 8:
            if self.deployment_mode == "saas":
                return PLATFORM_V8_SAAS
            return PLATFORM_V8_OPP
        return PLATFORM_V6

    @property
    def label(self) -> str:
        labels = {
            PLATFORM_V6: f"XSOAR 6 ({self.version})",
            PLATFORM_V8_OPP: f"XSOAR 8 OPP ({self.version})",
            PLATFORM_V8_SAAS: f"XSOAR 8 SaaS ({self.version})",
            PLATFORM_XSIAM: f"XSIAM ({self.version})",
        }
        return labels.get(self.platform, f"Unknown ({self.version})")

    @property
    def is_v8(self) -> bool:
        return self.major >= 8

    @property
    def is_xsiam(self) -> bool:
        return self.product_mode == "xsiam"


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


def render_hcl_block(block_type: str, block_name: str, attrs: Dict[str, Any],
                     indent: int = 2) -> str:
    """Render an HCL nested block (e.g. human_cron = { ... })."""
    pad = " " * indent
    lines = [f"{pad}{block_name} = {{"]
    for key, value in attrs.items():
        if isinstance(value, str) and value.startswith("var."):
            lines.append(f"{pad}  {key} = {value}")
        else:
            lines.append(f"{pad}  {key} = {hcl_value(value, indent + 2)}")
    lines.append(f"{pad}}}")
    return "\n".join(lines)


# --- XSOAR Client (API key auth) ---

class XSOARClient:
    """HTTP client for Cortex XSOAR/XSIAM REST API."""

    def __init__(self, base_url: str, api_key: str, insecure: bool = False,
                 auth_id: str = ""):
        self.base_url = base_url.rstrip("/")
        self.auth_id = auth_id
        self.is_v8 = bool(auth_id)
        # V8 uses /xsoar/ prefix for all API paths
        self.prefix = "/xsoar" if self.is_v8 else ""
        self.platform: Optional[PlatformInfo] = None
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

    def get_raw(self, path: str) -> bytes:
        """GET request returning raw response body (for non-JSON endpoints)."""
        resp = self.session.get(f"{self.base_url}{self.prefix}{path}")
        resp.raise_for_status()
        return resp.content

    def post(self, path: str, data: Any = None) -> Any:
        resp = self.session.post(f"{self.base_url}{self.prefix}{path}", json=data or {})
        resp.raise_for_status()
        return resp.json() if resp.content else None

    def detect_platform(self) -> PlatformInfo:
        """Detect platform version and type from /about endpoint."""
        about = self.get("/about")
        if not isinstance(about, dict):
            return PlatformInfo()

        version = about.get("demistoVersion", about.get("version", "unknown"))
        product_mode = about.get("productMode", "xsoar")
        deployment_mode = about.get("deploymentMode", "opp")

        # Parse major version
        major = 6
        if version and version != "unknown":
            try:
                major = int(version.split(".")[0])
            except (ValueError, IndexError):
                pass

        # If auth_id is set but major < 8, trust auth_id
        if self.is_v8 and major < 8:
            major = 8

        self.platform = PlatformInfo(
            version=version,
            major=major,
            product_mode=product_mode,
            deployment_mode=deployment_mode,
        )
        return self.platform


# --- Webapp Client (session auth) ---

def derive_ui_url(api_url: str) -> str:
    """Derive the UI URL from the API URL by removing the 'api-' prefix from hostname."""
    parsed = urlparse(api_url)
    hostname = parsed.hostname or ""
    if hostname.startswith("api-"):
        hostname = hostname[4:]
    port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    return f"{parsed.scheme}://{hostname}{port}"


class WebappClient:
    """HTTP client for Cortex XSIAM webapp API (session cookie auth)."""

    def __init__(self, ui_url: str, session_token: str = "", insecure: bool = False):
        self.ui_url = ui_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = not insecure
        self.csrf_token = ""
        self.xsrf_token = ""

        if session_token:
            parsed = urlparse(self.ui_url)
            domain = parsed.hostname or ""
            self.session.cookies.set("app-proxy-hydra-prod-us", session_token, domain=domain)
            self.session.cookies.set("app-hub", session_token, domain=domain)

    @classmethod
    def from_session_file(cls, insecure: bool = False) -> Optional["WebappClient"]:
        """Create a WebappClient from ~/.cortex/session.json if it exists."""
        session_path = os.path.join(os.path.expanduser("~"), ".cortex", "session.json")
        if not os.path.exists(session_path):
            return None
        try:
            with open(session_path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to read session file {session_path}: {e}")
            return None

        url = data.get("url", "")
        if not url:
            return None

        client = cls(url, insecure=insecure)

        parsed = urlparse(url)
        domain = parsed.hostname or ""

        # Set all cookies from session file
        cookies = data.get("all_cookies") or data.get("cookies") or {}
        for name, value in cookies.items():
            client.session.cookies.set(name, value, domain=domain)

        # XSRF/CSRF tokens
        if data.get("xsrf_token"):
            client.xsrf_token = data["xsrf_token"]
            client.session.cookies.set("XSRF-TOKEN", data["xsrf_token"], domain=domain)
        if data.get("csrf_token"):
            client.csrf_token = data["csrf_token"]
            client.session.cookies.set("csrf_token", data["csrf_token"], domain=domain)

        return client

    def post(self, path: str, data: Any = None) -> Any:
        """POST request with session auth headers."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-XDR-REQUEST-TOKEN": secrets.token_hex(16),
        }
        if self.csrf_token:
            headers["X-CSRF-TOKEN"] = self.csrf_token
        if self.xsrf_token:
            headers["X-XSRF-TOKEN"] = self.xsrf_token

        resp = self.session.post(
            f"{self.ui_url}{path}",
            json=data if data is not None else {},
            headers=headers,
            allow_redirects=False,
        )
        if 300 <= resp.status_code < 400:
            raise Exception(f"Session redirect (expired?): {resp.status_code} -> {resp.headers.get('Location', '?')}")
        resp.raise_for_status()
        return resp.json() if resp.content else None

    def grid_data(self, table_name: str, sort: Optional[List] = None) -> List[Dict]:
        """Fetch grid data from a named table."""
        filter_data = {
            "sort": sort or [],
            "filter": {},
            "paging": {"from": 0, "to": 500},
        }
        resp = self.post(
            f"/api/webapp/get_data?type=grid&table_name={table_name}",
            {"filter_data": filter_data},
        )
        if not resp or "reply" not in resp:
            return []
        reply = resp["reply"]
        if isinstance(reply, dict) and "DATA" in reply:
            return reply["DATA"] or []
        elif isinstance(reply, list):
            return reply
        return []

    def test_connection(self) -> bool:
        """Test if the webapp session is valid by fetching a small grid."""
        try:
            self.grid_data("CORRELATION_RULES")
            return True
        except Exception:
            return False


# --- Helper functions for grid data parsing ---

def grid_str(d: Dict, key: str) -> str:
    """Get a string value from a grid data row (UPPERCASE keys)."""
    v = d.get(key, "")
    if v is None:
        return ""
    return str(v)


def grid_int(d: Dict, key: str) -> int:
    """Get an integer value from a grid data row."""
    v = d.get(key, 0)
    if isinstance(v, (int, float)):
        return int(v)
    return 0


def grid_bool(d: Dict, key: str) -> bool:
    """Get a boolean value from a grid data row."""
    v = d.get(key, False)
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() in ("true", "1", "yes")
    return bool(v)


def grid_json(d: Dict, key: str) -> str:
    """Get a JSON-serialized value from a grid data row."""
    v = d.get(key)
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    return json.dumps(v)


def grid_list(d: Dict, key: str) -> List[str]:
    """Get a list of strings from a grid data row."""
    v = d.get(key, [])
    if isinstance(v, list):
        return [str(item) for item in v if item is not None]
    return []


# --- Standard API Exporters ---

SENSITIVE_PARAM_TYPES = {9, 14}  # 9=password, 14=encrypted

# Platform compatibility for each exporter.
EXPORTER_PLATFORMS = {
    "server_config":        {PLATFORM_V6, PLATFORM_V8_SAAS},
    "marketplace":          {PLATFORM_V6, PLATFORM_V8_OPP, PLATFORM_V8_SAAS, PLATFORM_XSIAM},
    "integrations":         {PLATFORM_V6, PLATFORM_V8_OPP, PLATFORM_V8_SAAS, PLATFORM_XSIAM},
    "roles":                {PLATFORM_V6, PLATFORM_V8_OPP, PLATFORM_V8_SAAS, PLATFORM_XSIAM},
    "api_keys":             {PLATFORM_V6},
    "jobs":                 {PLATFORM_V6, PLATFORM_V8_OPP, PLATFORM_V8_SAAS, PLATFORM_XSIAM},
    "preprocessing_rules":  {PLATFORM_V6},
    "password_policy":      {PLATFORM_V6, PLATFORM_V8_OPP, PLATFORM_V8_SAAS, PLATFORM_XSIAM},
    "credentials":          {PLATFORM_V6, PLATFORM_V8_OPP, PLATFORM_V8_SAAS, PLATFORM_XSIAM},
    "exclusion_list":       {PLATFORM_V6, PLATFORM_V8_OPP, PLATFORM_V8_SAAS, PLATFORM_XSIAM},
    "lists":                {PLATFORM_V6, PLATFORM_V8_OPP, PLATFORM_V8_SAAS, PLATFORM_XSIAM},
}

# Webapp API exporters (XSIAM only, session auth required)
WEBAPP_EXPORTER_PLATFORMS = {
    "correlation_rules":            {PLATFORM_XSIAM},
    "ioc_rules":                    {PLATFORM_XSIAM},
    "edl":                          {PLATFORM_XSIAM},
    "vulnerability_scan_settings":  {PLATFORM_XSIAM},
    "device_control_classes":       {PLATFORM_XSIAM},
    "custom_statuses":              {PLATFORM_XSIAM},
    "agent_groups":                 {PLATFORM_XSIAM},
    "incident_domains":             {PLATFORM_XSIAM},
    "tim_rules":                    {PLATFORM_XSIAM},
    "attack_surface_rules":         {PLATFORM_XSIAM},
    "bioc_rules":                   {PLATFORM_XSIAM},
    "rules_exceptions":             {PLATFORM_XSIAM},
    "analytics_detectors":          {PLATFORM_XSIAM},
    "fim_rule_groups":              {PLATFORM_XSIAM},
    "fim_rules":                    {PLATFORM_XSIAM},
    "notification_rules":           {PLATFORM_XSIAM},
    "auto_upgrade_settings":        {PLATFORM_XSIAM},
    "parsing_rules":                {PLATFORM_XSIAM},
    "data_modeling_rules":          {PLATFORM_XSIAM},
    "collector_groups":             {PLATFORM_XSIAM},
    "collector_distributions":      {PLATFORM_XSIAM},
    "collector_profiles":           {PLATFORM_XSIAM},
}


def export_server_config(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export server configuration as cortex_server_config resources."""
    try:
        data = client.get("/system/config")
    except Exception as e:
        logger.warning(f"Failed to fetch server config: {e}")
        return "", [], {}

    sys_conf = data.get("sysConf", {}) if isinstance(data, dict) else {}
    blocks = []
    imports = []

    skip_keys = {"versn", "dbwizard.status", "encryptedDBKey"}

    for key in sorted(sys_conf.keys()):
        if key in skip_keys:
            continue
        val = sys_conf[key]
        if isinstance(val, (dict, list)):
            continue
        tf_id = sanitize_tf_id(key)
        block = render_resource("cortex_server_config", tf_id, {
            "key": key,
            "value": str(val),
        }, comments=[f"Server config: {key}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_server_config.{tf_id} "{key}"')

    if not blocks:
        return "", [], {}
    content = "# Server Configuration\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
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
    content = "# Marketplace Packs\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
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
    content = "# Integration Instances\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
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

    is_readonly = client.platform and client.platform.is_v8
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

        comments = [f"Role: {name}"]
        if is_readonly:
            comments.append("WARNING: Roles are read-only on V8/XSIAM (managed at XDR platform level)")
            comments.append("This resource can be imported but not created/updated/deleted via Terraform")
        block = render_resource("cortex_role", tf_id, attrs, comments=comments)
        blocks.append(block)
        imports.append(f'terraform import cortex_role.{tf_id} "{name}"')

    if not blocks:
        return "", [], {}

    header = "# Roles\n# Generated by cortex-export\n"
    if is_readonly:
        header += "# WARNING: Roles are READ-ONLY on XSOAR 8 / XSIAM.\n"
        header += "# These resources can be imported but not created/updated/deleted.\n"
    content = header + "\n" + "\n\n".join(blocks)
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
    content = "# API Keys\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_jobs(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export jobs with full XSIAM field support."""
    try:
        data = client.post("/jobs/search", {"page": 0, "size": 500})
    except Exception as e:
        logger.warning(f"Failed to fetch jobs: {e}")
        return "", [], {}

    jobs = []
    if isinstance(data, dict):
        jobs = data.get("data") or []
    if not jobs:
        return "", [], {}

    is_xsiam = client.platform and client.platform.is_xsiam
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

        job_type = job.get("type", "")
        if job_type:
            attrs["type"] = job_type

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

        start_date = job.get("startDate", "")
        if start_date:
            attrs["start_date"] = start_date

        ending_date = job.get("endingDate", "")
        if ending_date:
            attrs["ending_date"] = ending_date

        ending_type = job.get("endingType", "")
        if ending_type:
            attrs["ending_type"] = ending_type

        human_cron = job.get("humanCron", {})
        if human_cron and isinstance(human_cron, dict):
            hc_attrs = {}
            if human_cron.get("timePeriodType"):
                hc_attrs["time_period_type"] = human_cron["timePeriodType"]
            if human_cron.get("timePeriod") is not None:
                hc_attrs["time_period"] = int(human_cron["timePeriod"])
            if human_cron.get("days"):
                hc_attrs["days"] = human_cron["days"]
            if hc_attrs:
                attrs["_human_cron"] = hc_attrs

        comments = [f"Job: {name}"]
        if is_xsiam and not human_cron:
            comments.append("WARNING: XSIAM requires human_cron + start_date for scheduled jobs")

        hc = attrs.pop("_human_cron", None)
        lines = []
        for c in comments:
            lines.append(f"# {c}")
        lines.append(f'resource "cortex_job" "{tf_id}" {{')
        for key, value in attrs.items():
            if isinstance(value, str) and value.startswith("var."):
                lines.append(f"  {key} = {value}")
            else:
                lines.append(f"  {key} = {hcl_value(value)}")
        if hc:
            lines.append("")
            lines.append("  human_cron = {")
            for k, v in hc.items():
                lines.append(f"    {k} = {hcl_value(v, 4)}")
            lines.append("  }")
        lines.append("}")
        block = "\n".join(lines)

        blocks.append(block)
        imports.append(f'terraform import cortex_job.{tf_id} "{name}"')

    if not blocks:
        return "", [], {}
    content = "# Jobs\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
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
    content = "# Pre-processing Rules\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
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
    content = "# Password Policy\n# Generated by cortex-export\n\n" + block
    imports = ['terraform import cortex_password_policy.main "password_policy"']
    return content, imports, {}


def export_credentials(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export credentials (passwords are not exported)."""
    try:
        resp = client.post("/settings/credentials", {})
    except Exception as e:
        logger.warning(f"Failed to fetch credentials: {e}")
        return "", [], {}

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
    content = "# Credentials\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
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
    content = "# Indicator Exclusion List\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_lists(client: XSOARClient) -> Tuple[str, List[str], Dict]:
    """Export lists (plain_text, json, html, markdown, css)."""
    try:
        all_lists = client.get("/lists")
    except Exception as e:
        logger.warning(f"Failed to fetch lists: {e}")
        return "", [], {}

    if not isinstance(all_lists, list) or not all_lists:
        return "", [], {}

    blocks = []
    imports = []
    names = [l.get("name", f"list_{i}") for i, l in enumerate(all_lists)]
    id_map = make_unique_ids(names)

    for list_meta in all_lists:
        name = list_meta.get("name", "")
        list_type = list_meta.get("type", "plain_text")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        try:
            data = client.get_raw(f"/lists/download/{name}").decode("utf-8", errors="replace")
        except Exception as e:
            logger.warning(f"Failed to download list '{name}': {e}")
            data = ""

        attrs = {
            "name": name,
            "type": list_type,
            "data": data,
        }

        block = render_resource("cortex_list", tf_id, attrs,
                                comments=[f"List: {name} (type: {list_type})"])
        blocks.append(block)
        imports.append(f'terraform import cortex_list.{tf_id} "{name}"')

    if not blocks:
        return "", [], {}
    content = "# Lists\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


# --- Webapp API Exporters (XSIAM only) ---


def export_correlation_rules(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM correlation rules."""
    try:
        rows = wc.grid_data("CORRELATION_RULES",
                            sort=[{"FIELD": "MODIFY_TIME", "ORDER": "DESC"}])
    except Exception as e:
        logger.warning(f"Failed to fetch correlation rules: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "NAME") or f"rule_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, "NAME")
        rule_id = grid_int(d, "RULE_ID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "severity": grid_str(d, "SEVERITY"),
            "status": grid_str(d, "STATUS"),
            "xql_query": grid_str(d, "XQL_QUERY"),
            "execution_mode": grid_str(d, "EXECUTION_MODE"),
            "dataset": grid_str(d, "DATASET"),
            "timezone": grid_str(d, "TIMEZONE"),
            "alert_domain": grid_str(d, "ALERT_DOMAIN"),
            "mapping_strategy": grid_str(d, "MAPPING_STRATEGY"),
            "action": grid_str(d, "ACTION"),
        }
        desc = grid_str(d, "DESCRIPTION")
        if desc:
            attrs["description"] = desc
        sw = grid_str(d, "SEARCH_WINDOW")
        if sw:
            attrs["search_window"] = sw
        ss = grid_str(d, "SIMPLE_SCHEDULE")
        if ss:
            attrs["simple_schedule"] = ss
        ac = grid_str(d, "ALERT_CATEGORY")
        if ac:
            attrs["alert_category"] = ac
        an = grid_str(d, "ALERT_NAME")
        if an:
            attrs["alert_name"] = an

        block = render_resource("cortex_correlation_rule", tf_id, attrs,
                                comments=[f"Correlation Rule: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_correlation_rule.{tf_id} "{rule_id}"')

    if not blocks:
        return "", [], {}
    content = "# Correlation Rules (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_ioc_rules(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM IOC rules."""
    try:
        rows = wc.grid_data("IOC_RULE_TABLE",
                            sort=[{"FIELD": "RULE_MODIFY_TIME", "ORDER": "DESC"}])
    except Exception as e:
        logger.warning(f"Failed to fetch IOC rules: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "RULE_INDICATOR") or f"ioc_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        indicator = grid_str(d, "RULE_INDICATOR")
        rule_id = grid_int(d, "RULE_ID")
        tf_id = id_map.get(indicator, sanitize_tf_id(indicator))

        attrs = {
            "severity": grid_str(d, "RULE_SEVERITY"),
            "indicator": indicator,
            "ioc_type": grid_str(d, "IOC_TYPE"),
        }
        comment = grid_str(d, "RULE_COMMENT")
        if comment:
            attrs["comment"] = comment
        is_default_ttl = grid_bool(d, "IS_DEFAULT_TTL")
        attrs["is_default_ttl"] = is_default_ttl
        rep = grid_str(d, "REPUTATION")
        if rep:
            attrs["reputation"] = rep
        rel = grid_str(d, "RELIABILITY")
        if rel:
            attrs["reliability"] = rel

        block = render_resource("cortex_ioc_rule", tf_id, attrs,
                                comments=[f"IOC Rule: {indicator} ({grid_str(d, 'IOC_TYPE')})"])
        blocks.append(block)
        imports.append(f'terraform import cortex_ioc_rule.{tf_id} "{rule_id}"')

    if not blocks:
        return "", [], {}
    content = "# IOC Rules (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_edl(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM EDL configuration (singleton)."""
    try:
        resp = wc.post("/api/webapp/edl/get_edl_status", {})
    except Exception as e:
        logger.warning(f"Failed to fetch EDL config: {e}")
        return "", [], {}

    reply = (resp or {}).get("reply", {})
    if not isinstance(reply, dict):
        return "", [], {}

    variables = {}
    var_name = "edl_password"
    variables[var_name] = {
        "description": "EDL HTTP basic auth password",
        "sensitive": True,
    }

    attrs = {
        "enabled": reply.get("edl_is_enabled", False),
        "username": reply.get("username", ""),
        "password": f"var.{var_name}",
    }

    block = render_resource("cortex_edl", "main", attrs,
                            comments=["EDL Configuration (XSIAM, singleton)",
                                      "NOTE: Password must be provided via variable"])
    content = "# EDL Configuration (XSIAM)\n# Generated by cortex-export\n\n" + block
    imports = ['terraform import cortex_edl.main "edl"']
    return content, imports, variables


def export_vulnerability_scan_settings(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM vulnerability scan settings (singleton)."""
    try:
        resp = wc.post("/api/webapp/vulnerability_tests/get_settings", {})
    except Exception as e:
        logger.warning(f"Failed to fetch vulnerability scan settings: {e}")
        return "", [], {}

    if not isinstance(resp, dict):
        return "", [], {}

    attrs = {
        "eula_accepted": resp.get("EULA_ACCEPTED", False),
    }
    if "NEW_TESTS_ENABLED" in resp:
        attrs["new_tests_enabled"] = resp["NEW_TESTS_ENABLED"]
    if "PAUSE_TESTING" in resp:
        attrs["pause_testing"] = resp["PAUSE_TESTING"]
    if "RUN_TESTS_ON_ALL_SERVICES" in resp:
        attrs["run_tests_on_all_services"] = resp["RUN_TESTS_ON_ALL_SERVICES"]
    if "INTRUSIVE_LEVEL" in resp:
        attrs["intrusive_level"] = int(resp["INTRUSIVE_LEVEL"])
    if resp.get("TARGET_FILTER"):
        attrs["target_filter"] = resp["TARGET_FILTER"]

    block = render_resource("cortex_vulnerability_scan_settings", "main", attrs,
                            comments=["Vulnerability Scan Settings (XSIAM, singleton)"])
    content = "# Vulnerability Scan Settings (XSIAM)\n# Generated by cortex-export\n\n" + block
    imports = ['terraform import cortex_vulnerability_scan_settings.main "vulnerability_scan_settings"']
    return content, imports, {}


def export_device_control_classes(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM device control classes."""
    try:
        resp = wc.post("/api/webapp/device_control/user_defined/get_classes", {})
    except Exception as e:
        logger.warning(f"Failed to fetch device control classes: {e}")
        return "", [], {}

    items = (resp or {}).get("reply", [])
    if not isinstance(items, list) or not items:
        return "", [], {}

    blocks = []
    imports = []
    names = [d.get("identifier", f"class_{i}") for i, d in enumerate(items)]
    id_map = make_unique_ids(names)

    for d in items:
        identifier = d.get("identifier", "")
        dev_type = d.get("type", "")
        tf_id = id_map.get(identifier, sanitize_tf_id(identifier))

        attrs = {
            "identifier": identifier,
            "type": dev_type,
        }

        block = render_resource("cortex_device_control_class", tf_id, attrs,
                                comments=[f"Device Control Class: {identifier}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_device_control_class.{tf_id} "{identifier}"')

    if not blocks:
        return "", [], {}
    content = "# Device Control Classes (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_custom_statuses(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM custom statuses (only user-defined, can_delete=true)."""
    try:
        resp = wc.post("/api/webapp/custom_status/get_statuses", {})
    except Exception as e:
        logger.warning(f"Failed to fetch custom statuses: {e}")
        return "", [], {}

    reply = (resp or {}).get("reply", {})
    if not isinstance(reply, dict):
        return "", [], {}

    blocks = []
    imports = []

    for status_type, key in [("status", "statuses"), ("resolution", "resolutionStatuses")]:
        for d in reply.get(key, []):
            if not d.get("can_delete", False):
                continue  # Skip system-defined statuses

            enum_name = d.get("enum_name", "")
            pretty_name = d.get("pretty_name", "")
            tf_id = sanitize_tf_id(pretty_name or enum_name)

            attrs = {
                "pretty_name": pretty_name,
                "status_type": status_type,
            }
            if "priority" in d:
                attrs["priority"] = int(d["priority"])

            block = render_resource("cortex_custom_status", tf_id, attrs,
                                    comments=[f"Custom Status: {pretty_name} ({status_type})"])
            blocks.append(block)
            imports.append(f'terraform import cortex_custom_status.{tf_id} "{enum_name}"')

    if not blocks:
        return "", [], {}
    content = "# Custom Statuses (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_agent_groups(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM agent groups."""
    try:
        rows = wc.grid_data("AGENT_GROUPS_TABLE")
    except Exception as e:
        logger.warning(f"Failed to fetch agent groups: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "NAME") or f"group_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, "NAME")
        group_id = grid_int(d, "GROUP_ID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "type": grid_str(d, "TYPE"),
        }
        desc = grid_str(d, "DESCRIPTION")
        if desc:
            attrs["description"] = desc
        filt = grid_json(d, "FILTER")
        if filt and filt != "null":
            attrs["filter"] = filt

        block = render_resource("cortex_agent_group", tf_id, attrs,
                                comments=[f"Agent Group: {name} ({grid_str(d, 'TYPE')})"])
        blocks.append(block)
        imports.append(f'terraform import cortex_agent_group.{tf_id} "{group_id}"')

    if not blocks:
        return "", [], {}
    content = "# Agent Groups (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_incident_domains(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM incident domains."""
    try:
        resp = wc.post("/api/webapp/incident_domains/get_domains/", {})
    except Exception as e:
        logger.warning(f"Failed to fetch incident domains: {e}")
        return "", [], {}

    reply = (resp or {}).get("reply", {})
    if isinstance(reply, dict):
        items = reply.get("domains", [])
    elif isinstance(reply, list):
        items = reply
    else:
        return "", [], {}
    if not items:
        return "", [], {}

    blocks = []
    imports = []
    names = [d.get("PRETTY_NAME", f"domain_{i}") for i, d in enumerate(items)]
    id_map = make_unique_ids(names)

    for d in items:
        pretty_name = d.get("PRETTY_NAME", "")
        domain_id = d.get("ID", 0)
        if isinstance(domain_id, float):
            domain_id = int(domain_id)
        tf_id = id_map.get(pretty_name, sanitize_tf_id(pretty_name))

        attrs = {
            "pretty_name": pretty_name,
            "color": d.get("COLOR", ""),
        }
        desc = d.get("DESCRIPTION", "")
        if desc:
            attrs["description"] = desc

        statuses = d.get("STATUSES", [])
        if isinstance(statuses, list):
            attrs["statuses"] = [str(s) for s in statuses]
        resolved = d.get("RESOLVED_STATUSES", [])
        if isinstance(resolved, list):
            attrs["resolved_statuses"] = [str(s) for s in resolved]

        block = render_resource("cortex_incident_domain", tf_id, attrs,
                                comments=[f"Incident Domain: {pretty_name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_incident_domain.{tf_id} "{domain_id}"')

    if not blocks:
        return "", [], {}
    content = "# Incident Domains (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_tim_rules(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM TIM rules."""
    try:
        rows = wc.grid_data("TIM_RULES_TABLE")
    except Exception as e:
        logger.warning(f"Failed to fetch TIM rules: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "NAME") or f"rule_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, "NAME")
        rule_id = grid_int(d, "RULE_ID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "type": grid_str(d, "TYPE"),
            "severity": grid_str(d, "SEVERITY"),
            "status": grid_str(d, "STATUS"),
            "target": grid_json(d, "TARGET"),
        }
        desc = grid_str(d, "DESCRIPTION")
        if desc:
            attrs["description"] = desc

        block = render_resource("cortex_tim_rule", tf_id, attrs,
                                comments=[f"TIM Rule: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_tim_rule.{tf_id} "{rule_id}"')

    if not blocks:
        return "", [], {}
    content = "# TIM Rules (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_attack_surface_rules(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM attack surface rules (system-defined, update-only)."""
    try:
        rows = wc.grid_data("ATTACK_SURFACE_RULES_TABLE")
    except Exception as e:
        logger.warning(f"Failed to fetch attack surface rules: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "ISSUE_TYPE_ID") or f"rule_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        issue_type_id = grid_str(d, "ISSUE_TYPE_ID")
        tf_id = id_map.get(issue_type_id, sanitize_tf_id(issue_type_id))

        attrs = {
            "issue_type_id": issue_type_id,
            "enabled_status": grid_str(d, "ENABLED_STATUS"),
            "priority": grid_str(d, "PRIORITY"),
        }

        block = render_resource("cortex_attack_surface_rule", tf_id, attrs,
                                comments=[f"Attack Surface Rule: {grid_str(d, 'ISSUE_TYPE_NAME')}",
                                          "System-defined rule (update-only, no create/delete)"])
        blocks.append(block)
        imports.append(f'terraform import cortex_attack_surface_rule.{tf_id} "{issue_type_id}"')

    if not blocks:
        return "", [], {}
    header = "# Attack Surface Rules (XSIAM)\n# Generated by cortex-export\n"
    header += "# NOTE: These are system-defined rules. Only enabled_status and priority can be changed.\n"
    content = header + "\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_bioc_rules(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM BIOC rules."""
    try:
        rows = wc.grid_data("BIOC_RULE_TABLE")
    except Exception as e:
        logger.warning(f"Failed to fetch BIOC rules: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "RULE_NAME") or f"rule_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, "RULE_NAME")
        rule_id = grid_int(d, "RULE_ID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "severity": grid_str(d, "RULE_SEVERITY"),
            "status": grid_str(d, "RULE_STATUS"),
            "category": grid_str(d, "BIOC_CATEGORY"),
            "indicator_text": grid_json(d, "RULE_INDICATOR_TEXT"),
        }
        comment = grid_str(d, "RULE_COMMENT")
        if comment:
            attrs["comment"] = comment
        is_xql = grid_bool(d, "IS_XQL")
        if is_xql:
            attrs["is_xql"] = True
        tactics = grid_list(d, "MITRE_TACTIC_ID")
        if tactics:
            attrs["mitre_tactic"] = tactics
        techniques = grid_list(d, "MITRE_TECHNIQUE_ID")
        if techniques:
            attrs["mitre_technique"] = techniques

        block = render_resource("cortex_bioc_rule", tf_id, attrs,
                                comments=[f"BIOC Rule: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_bioc_rule.{tf_id} "{rule_id}"')

    if not blocks:
        return "", [], {}
    content = "# BIOC Rules (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_rules_exceptions(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM rules exceptions."""
    try:
        rows = wc.grid_data("RULES_EXCEPTIONS_TABLE")
    except Exception as e:
        logger.warning(f"Failed to fetch rules exceptions: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "RULE_NAME") or f"exception_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, "RULE_NAME")
        exception_id = grid_int(d, "EXCEPTION_ID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "indicator_text": grid_json(d, "EXCEPTION_INDICATOR_TEXT"),
        }
        comment = grid_str(d, "EXCEPTION_COMMENT")
        if comment:
            attrs["comment"] = comment

        block = render_resource("cortex_rules_exception", tf_id, attrs,
                                comments=[f"Rules Exception: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_rules_exception.{tf_id} "{exception_id}"')

    if not blocks:
        return "", [], {}
    content = "# Rules Exceptions (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_analytics_detectors(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM analytics detectors (system-defined, update-only)."""
    try:
        rows = wc.grid_data("ANALYTICS_DETECTORS_TABLE")
    except Exception as e:
        logger.warning(f"Failed to fetch analytics detectors: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "GLOBAL_RULE_ID") or f"detector_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        global_rule_id = grid_str(d, "GLOBAL_RULE_ID")
        tf_id = id_map.get(global_rule_id, sanitize_tf_id(global_rule_id))

        attrs = {
            "global_rule_id": global_rule_id,
            "severity": grid_str(d, "RULE_SEVERITY"),
            "status": grid_str(d, "RULE_STATUS"),
        }

        block = render_resource("cortex_analytics_detector", tf_id, attrs,
                                comments=[f"Analytics Detector: {grid_str(d, 'RULE_NAME')}",
                                          "System-defined detector (only severity and status are mutable)"])
        blocks.append(block)
        imports.append(f'terraform import cortex_analytics_detector.{tf_id} "{global_rule_id}"')

    if not blocks:
        return "", [], {}
    header = "# Analytics Detectors (XSIAM)\n# Generated by cortex-export\n"
    header += "# NOTE: These are system-defined detectors. Only severity and status can be changed.\n"
    content = header + "\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_fim_rule_groups(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM FIM rule groups."""
    try:
        rows = wc.grid_data("FILE_INTEGRITY_MONITORING_RULE_GROUPS")
    except Exception as e:
        logger.warning(f"Failed to fetch FIM rule groups: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "NAME") or f"group_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, "NAME")
        group_id = grid_int(d, "ID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "os_type": grid_str(d, "OS_TYPE"),
        }
        desc = grid_str(d, "DESCRIPTION")
        if desc:
            attrs["description"] = desc
        mm = grid_str(d, "MONITORING_MODE")
        if mm:
            attrs["monitoring_mode"] = mm

        block = render_resource("cortex_fim_rule_group", tf_id, attrs,
                                comments=[f"FIM Rule Group: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_fim_rule_group.{tf_id} "{group_id}"')

    if not blocks:
        return "", [], {}
    content = "# FIM Rule Groups (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_fim_rules(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM FIM rules."""
    try:
        rows = wc.grid_data("FILE_INTEGRITY_MONITORING_RULES")
    except Exception as e:
        logger.warning(f"Failed to fetch FIM rules: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "PATH") or f"rule_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        path = grid_str(d, "PATH")
        rule_id = grid_int(d, "ID")
        tf_id = id_map.get(path, sanitize_tf_id(path))

        attrs = {
            "type": grid_str(d, "TYPE"),
            "path": path,
            "group_id": grid_int(d, "GROUP_ID"),
        }
        desc = grid_str(d, "DESCRIPTION")
        if desc:
            attrs["description"] = desc
        if grid_bool(d, "MONITOR_ALL_EVENTS"):
            attrs["monitor_all_events"] = True

        block = render_resource("cortex_fim_rule", tf_id, attrs,
                                comments=[f"FIM Rule: {path} ({grid_str(d, 'TYPE')})"])
        blocks.append(block)
        imports.append(f'terraform import cortex_fim_rule.{tf_id} "{rule_id}"')

    if not blocks:
        return "", [], {}
    content = "# FIM Rules (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_notification_rules(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM notification rules."""
    try:
        rows = wc.grid_data("ALERT_NOTIFICATION_RULES")
    except Exception as e:
        logger.warning(f"Failed to fetch notification rules: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    prefix = "ALERT_NOTIFICATION_RULES_"
    names = [grid_str(r, f"{prefix}NAME") or f"rule_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, f"{prefix}NAME")
        rule_id = grid_int(d, f"{prefix}ID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "forward_type": grid_str(d, f"{prefix}TYPE"),
        }
        desc = grid_str(d, f"{prefix}DESCRIPTION")
        if desc:
            attrs["description"] = desc
        filt = grid_json(d, f"{prefix}FILTER")
        if filt and filt != "null":
            attrs["filter"] = filt
        emails = grid_list(d, f"{prefix}EMAIL_DISTRIBUTION_LIST")
        if emails:
            attrs["email_distribution_list"] = emails
        agg = grid_int(d, f"{prefix}EMAIL_AGGREGATION")
        if agg:
            attrs["email_aggregation"] = agg
        syslog_list = grid_list(d, f"{prefix}SYSLOG_DISTRIBUTION_LIST")
        if syslog_list:
            attrs["syslog_enabled"] = True
        attrs["enabled"] = grid_bool(d, f"{prefix}ENABLED")

        block = render_resource("cortex_notification_rule", tf_id, attrs,
                                comments=[f"Notification Rule: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_notification_rule.{tf_id} "{rule_id}"')

    if not blocks:
        return "", [], {}
    content = "# Notification Rules (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_auto_upgrade_settings(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM auto-upgrade settings (singleton)."""
    try:
        resp = wc.post("/api/webapp/scouter_agents/auto_upgrade/get_auto_upgrade_global_settings", {})
    except Exception as e:
        logger.warning(f"Failed to fetch auto upgrade settings: {e}")
        return "", [], {}

    reply = (resp or {}).get("reply", {})
    if not isinstance(reply, dict):
        return "", [], {}

    attrs = {}
    time_settings = reply.get("TIME_SETTINGS", {})
    if isinstance(time_settings, dict):
        if time_settings.get("START_TIME"):
            attrs["start_time"] = time_settings["START_TIME"]
        if time_settings.get("END_TIME"):
            attrs["end_time"] = time_settings["END_TIME"]
        days = time_settings.get("DAYS")
        if isinstance(days, list) and days:
            attrs["days"] = [str(d) for d in days]

    batch_settings = reply.get("BATCH_SETTINGS", {})
    if isinstance(batch_settings, dict) and "BATCH_SIZE" in batch_settings:
        attrs["batch_size"] = int(batch_settings["BATCH_SIZE"])

    if not attrs:
        return "", [], {}

    block = render_resource("cortex_auto_upgrade_settings", "main", attrs,
                            comments=["Auto Upgrade Settings (XSIAM, singleton)"])
    content = "# Auto Upgrade Settings (XSIAM)\n# Generated by cortex-export\n\n" + block
    imports = ['terraform import cortex_auto_upgrade_settings.main "auto_upgrade_settings"']
    return content, imports, {}


def export_parsing_rules(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM parsing rules (singleton)."""
    try:
        resp = wc.post("/api/webapp/ingestion/xql/rule_files/user/get", {})
    except Exception as e:
        logger.warning(f"Failed to fetch parsing rules: {e}")
        return "", [], {}

    reply = (resp or {}).get("reply", {})
    text = reply.get("text", "")
    if not text:
        return "", [], {}

    attrs = {
        "text": text,
    }

    block = render_resource("cortex_parsing_rules", "main", attrs,
                            comments=["Parsing Rules (XSIAM, singleton)"])
    content = "# Parsing Rules (XSIAM)\n# Generated by cortex-export\n\n" + block
    imports = ['terraform import cortex_parsing_rules.main "parsing_rules"']
    return content, imports, {}


def export_data_modeling_rules(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM data modeling rules (singleton)."""
    try:
        resp = wc.post("/api/webapp/xdm/xql/mappings_files/user/get", {})
    except Exception as e:
        logger.warning(f"Failed to fetch data modeling rules: {e}")
        return "", [], {}

    reply = (resp or {}).get("reply", {})
    text = reply.get("text", "")
    if not text:
        return "", [], {}

    attrs = {
        "text": text,
    }

    block = render_resource("cortex_data_modeling_rules", "main", attrs,
                            comments=["Data Modeling Rules (XSIAM, singleton)"])
    content = "# Data Modeling Rules (XSIAM)\n# Generated by cortex-export\n\n" + block
    imports = ['terraform import cortex_data_modeling_rules.main "data_modeling_rules"']
    return content, imports, {}


def export_collector_groups(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM collector groups."""
    try:
        rows = wc.grid_data("SCOUTER_AGENT_GROUPS_TABLE")
    except Exception as e:
        logger.warning(f"Failed to fetch collector groups: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "NAME") or f"group_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, "NAME")
        group_id = grid_int(d, "GROUP_ID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "type": grid_str(d, "TYPE"),
        }
        desc = grid_str(d, "DESCRIPTION")
        if desc:
            attrs["description"] = desc
        filt = grid_json(d, "FILTER")
        if filt and filt != "null":
            attrs["filter"] = filt

        block = render_resource("cortex_collector_group", tf_id, attrs,
                                comments=[f"Collector Group: {name} ({grid_str(d, 'TYPE')})"])
        blocks.append(block)
        imports.append(f'terraform import cortex_collector_group.{tf_id} "{group_id}"')

    if not blocks:
        return "", [], {}
    content = "# Collector Groups (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_collector_distributions(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM collector distributions."""
    try:
        rows = wc.grid_data("SCOUTER_AGENT_DISTRIBUTIONS_TABLE")
    except Exception as e:
        logger.warning(f"Failed to fetch collector distributions: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "DIST_NAME") or f"dist_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, "DIST_NAME")
        dist_id = grid_str(d, "DIST_GUID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        attrs = {
            "name": name,
            "agent_version": grid_str(d, "DIST_AGENT_VERSION"),
            "platform": grid_str(d, "DIST_PLATFORM"),
        }
        desc = grid_str(d, "DIST_DESCRIPTION")
        if desc:
            attrs["description"] = desc
        pkg = grid_str(d, "DIST_TYPE")
        if pkg:
            attrs["package_type"] = pkg

        block = render_resource("cortex_collector_distribution", tf_id, attrs,
                                comments=[f"Collector Distribution: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_collector_distribution.{tf_id} "{dist_id}"')

    if not blocks:
        return "", [], {}
    content = "# Collector Distributions (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


def export_collector_profiles(wc: WebappClient) -> Tuple[str, List[str], Dict]:
    """Export XSIAM collector profiles."""
    try:
        rows = wc.grid_data("SCOUTER_AGENT_PROFILES_TABLE")
    except Exception as e:
        logger.warning(f"Failed to fetch collector profiles: {e}")
        return "", [], {}

    if not rows:
        return "", [], {}

    blocks = []
    imports = []
    names = [grid_str(r, "PROFILE_NAME") or f"profile_{i}" for i, r in enumerate(rows)]
    id_map = make_unique_ids(names)

    for d in rows:
        name = grid_str(d, "PROFILE_NAME")
        profile_id = grid_int(d, "PROFILE_ID")
        tf_id = id_map.get(name, sanitize_tf_id(name))

        # Extract modules (base64-encoded YAML)
        modules = ""
        modules_data = d.get("PROFILE_MODULES")
        if isinstance(modules_data, dict):
            fb = modules_data.get("filebeat", {})
            if isinstance(fb, dict):
                yaml_data = fb.get("yaml", {})
                if isinstance(yaml_data, dict):
                    modules = yaml_data.get("value", "")

        attrs = {
            "name": name,
            "platform": grid_str(d, "PROFILE_PLATFORM"),
            "modules": modules,
        }
        desc = grid_str(d, "PROFILE_DESCRIPTION")
        if desc:
            attrs["description"] = desc
        pt = grid_str(d, "PROFILE_TYPE")
        if pt:
            attrs["profile_type"] = pt
        if grid_bool(d, "PROFILE_IS_DEFAULT"):
            attrs["is_default"] = True

        block = render_resource("cortex_collector_profile", tf_id, attrs,
                                comments=[f"Collector Profile: {name}"])
        blocks.append(block)
        imports.append(f'terraform import cortex_collector_profile.{tf_id} "{profile_id}"')

    if not blocks:
        return "", [], {}
    content = "# Collector Profiles (XSIAM)\n# Generated by cortex-export\n\n" + "\n\n".join(blocks)
    return content, imports, {}


# --- Orchestrator ---

EXPORTERS = {
    "server_config":       ("server_config.tf", export_server_config),
    "marketplace":         ("marketplace_packs.tf", export_marketplace_packs),
    "integrations":        ("integration_instances.tf", export_integration_instances),
    "roles":               ("roles.tf", export_roles),
    "api_keys":            ("api_keys.tf", export_api_keys),
    "jobs":                ("jobs.tf", export_jobs),
    "preprocessing_rules": ("preprocessing_rules.tf", export_preprocessing_rules),
    "password_policy":     ("password_policy.tf", export_password_policy),
    "credentials":         ("credentials.tf", export_credentials),
    "exclusion_list":      ("exclusion_list.tf", export_exclusion_list),
    "lists":               ("lists.tf", export_lists),
}

WEBAPP_EXPORTERS = {
    "correlation_rules":            ("correlation_rules.tf", export_correlation_rules),
    "ioc_rules":                    ("ioc_rules.tf", export_ioc_rules),
    "edl":                          ("edl.tf", export_edl),
    "vulnerability_scan_settings":  ("vulnerability_scan_settings.tf", export_vulnerability_scan_settings),
    "device_control_classes":       ("device_control_classes.tf", export_device_control_classes),
    "custom_statuses":              ("custom_statuses.tf", export_custom_statuses),
    "agent_groups":                 ("agent_groups.tf", export_agent_groups),
    "incident_domains":             ("incident_domains.tf", export_incident_domains),
    "tim_rules":                    ("tim_rules.tf", export_tim_rules),
    "attack_surface_rules":         ("attack_surface_rules.tf", export_attack_surface_rules),
    "bioc_rules":                   ("bioc_rules.tf", export_bioc_rules),
    "rules_exceptions":             ("rules_exceptions.tf", export_rules_exceptions),
    "analytics_detectors":          ("analytics_detectors.tf", export_analytics_detectors),
    "fim_rule_groups":              ("fim_rule_groups.tf", export_fim_rule_groups),
    "fim_rules":                    ("fim_rules.tf", export_fim_rules),
    "notification_rules":           ("notification_rules.tf", export_notification_rules),
    "auto_upgrade_settings":        ("auto_upgrade_settings.tf", export_auto_upgrade_settings),
    "parsing_rules":                ("parsing_rules.tf", export_parsing_rules),
    "data_modeling_rules":          ("data_modeling_rules.tf", export_data_modeling_rules),
    "collector_groups":             ("collector_groups.tf", export_collector_groups),
    "collector_distributions":      ("collector_distributions.tf", export_collector_distributions),
    "collector_profiles":           ("collector_profiles.tf", export_collector_profiles),
}


def write_main_tf(output_dir: str, auth_id: str, has_webapp: bool):
    """Write the main.tf provider configuration."""
    auth_id_line = ""
    if auth_id:
        auth_id_line = '  auth_id        = var.xsoar_auth_id\n'

    session_token_line = ""
    if has_webapp:
        session_token_line = '  session_token  = var.xsoar_session_token\n'

    content = f'''# Generated by cortex-export
terraform {{
  required_providers {{
    cortex = {{
      source  = "mdrobniu/cortex"
      version = "~> 0.2"
    }}
  }}
}}

provider "cortex" {{
  base_url      = var.xsoar_url
  api_key       = var.xsoar_api_key
{auth_id_line}{session_token_line}  insecure      = var.xsoar_insecure
}}
'''
    with open(os.path.join(output_dir, "main.tf"), "w") as f:
        f.write(content)


def write_variables_tf(output_dir: str, variables: Dict[str, Dict], auth_id: str,
                       has_webapp: bool):
    """Write the variables.tf file."""
    lines = [
        "# Variables for Cortex Terraform configuration",
        "# Generated by cortex-export",
        "",
        'variable "xsoar_url" {',
        '  description = "XSOAR/XSIAM API base URL"',
        "  type        = string",
        "}",
        "",
        'variable "xsoar_api_key" {',
        '  description = "API key"',
        "  type        = string",
        "  sensitive   = true",
        "}",
        "",
    ]

    if auth_id:
        lines.extend([
            'variable "xsoar_auth_id" {',
            '  description = "Auth ID (XSOAR 8 / XSIAM)"',
            "  type        = string",
            f'  default     = "{auth_id}"',
            "}",
            "",
        ])

    if has_webapp:
        lines.extend([
            'variable "xsoar_session_token" {',
            '  description = "Session token for XSIAM webapp API (from browser or cortex-login)"',
            "  type        = string",
            "  sensitive   = true",
            '  default     = ""',
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
                         url: str, auth_id: str, has_webapp: bool):
    """Write terraform.tfvars.example."""
    lines = [
        "# Example variable values - copy to terraform.tfvars and fill in",
        "# Generated by cortex-export",
        "",
        f'xsoar_url      = "{url}"',
        'xsoar_api_key  = "YOUR_API_KEY_HERE"',
    ]
    if auth_id:
        lines.append(f'xsoar_auth_id  = "{auth_id}"')
    if has_webapp:
        lines.append('xsoar_session_token = ""  # Run cortex-login or paste from browser DevTools')
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
        "# Terraform import commands for XSOAR/XSIAM resources",
        "# Generated by cortex-export",
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


def run_export(client: XSOARClient, webapp_client: Optional[WebappClient],
               output_dir: str, resource_types: Optional[List[str]],
               save_raw: bool, url: str, auth_id: str):
    """Run the full export pipeline."""
    os.makedirs(output_dir, exist_ok=True)

    if save_raw:
        os.makedirs(os.path.join(output_dir, "raw"), exist_ok=True)

    all_imports = []
    all_variables = {}
    has_webapp = False

    platform = client.platform.platform if client.platform else PLATFORM_V6

    # Merge all platform maps
    all_platforms = {}
    all_platforms.update(EXPORTER_PLATFORMS)
    all_platforms.update(WEBAPP_EXPORTER_PLATFORMS)

    # Determine which exporters to run
    if resource_types is None:
        keys_to_run = list(EXPORTERS.keys()) + list(WEBAPP_EXPORTERS.keys())
    else:
        keys_to_run = [r.strip() for r in resource_types]

    for key in keys_to_run:
        # Check platform compatibility
        allowed = all_platforms.get(key, set())
        if platform not in allowed:
            if key in all_platforms:
                print(f"  Skipping {key} (not available on {client.platform.label if client.platform else 'this platform'})")
            continue

        # Determine which dict contains this exporter
        is_webapp_exporter = key in WEBAPP_EXPORTERS
        is_api_exporter = key in EXPORTERS

        if is_webapp_exporter:
            if webapp_client is None:
                print(f"  Skipping {key} (requires --session-token or ~/.cortex/session.json)")
                continue
            filename, exporter_fn = WEBAPP_EXPORTERS[key]
        elif is_api_exporter:
            filename, exporter_fn = EXPORTERS[key]
        else:
            print(f"  Skipping {key} (unknown resource type)")
            continue

        print(f"  Exporting {key}...")
        try:
            if is_webapp_exporter:
                content, imports, variables = exporter_fn(webapp_client)
                if content:
                    has_webapp = True
            else:
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
    write_main_tf(output_dir, auth_id, has_webapp)
    write_variables_tf(output_dir, all_variables, auth_id, has_webapp)
    write_tfvars_example(output_dir, all_variables, url, auth_id, has_webapp)
    write_import_sh(output_dir, all_imports)

    print(f"\nExport complete!")
    print(f"  Output directory: {output_dir}")
    print(f"  Total import commands: {len(all_imports)}")
    print(f"  Variables to configure: {len(all_variables)}")
    if has_webapp:
        print(f"  XSIAM webapp resources exported (session_token required in provider config)")
    print(f"\nNext steps:")
    print(f"  1. cd {output_dir}")
    print(f"  2. cp terraform.tfvars.example terraform.tfvars")
    print(f"  3. Edit terraform.tfvars with actual values")
    print(f"  4. terraform init")
    print(f"  5. bash import.sh")
    print(f"  6. terraform plan")


def main():
    parser = argparse.ArgumentParser(
        prog="cortex-export",
        description="Export Cortex XSOAR/XSIAM configuration as Terraform .tf files"
    )
    parser.add_argument("--url", default=os.environ.get("DEMISTO_BASE_URL"),
                        help="XSOAR/XSIAM API base URL (or DEMISTO_BASE_URL env var)")
    parser.add_argument("--api-key", default=os.environ.get("DEMISTO_API_KEY"),
                        help="API key (or DEMISTO_API_KEY env var)")
    parser.add_argument("--auth-id", default=os.environ.get("DEMISTO_AUTH_ID", ""),
                        help="Auth ID for XSOAR 8 / XSIAM (or DEMISTO_AUTH_ID env var)")
    parser.add_argument("--session-token", default=os.environ.get("CORTEX_SESSION_TOKEN", ""),
                        help="Session token for XSIAM webapp API (from browser DevTools or cortex-login)")
    parser.add_argument("--insecure", action="store_true",
                        default=bool(os.environ.get("DEMISTO_INSECURE")),
                        help="Skip TLS certificate verification")
    parser.add_argument("--output-dir", "-o", default="./cortex-terraform",
                        help="Output directory (default: ./cortex-terraform)")
    parser.add_argument("--resources", "-r", default="all",
                        help=f"Comma-separated resource types to export (default: all). "
                             f"Available: {', '.join(list(EXPORTERS.keys()) + list(WEBAPP_EXPORTERS.keys()))}")
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

    # Test connection and detect platform
    print(f"Connecting to {args.url}...")
    try:
        platform = client.detect_platform()
        print(f"  Connected to {platform.label}")
    except Exception as e:
        print(f"  ERROR: Could not connect: {e}", file=sys.stderr)
        sys.exit(1)

    # Set up webapp client for XSIAM
    webapp_client = None
    if platform.is_xsiam:
        if args.session_token:
            ui_url = derive_ui_url(args.url)
            webapp_client = WebappClient(ui_url, session_token=args.session_token,
                                         insecure=args.insecure)
            print(f"  Webapp client: session token -> {ui_url}")
        else:
            # Try loading from ~/.cortex/session.json
            webapp_client = WebappClient.from_session_file(insecure=args.insecure)
            if webapp_client:
                print(f"  Webapp client: session file -> {webapp_client.ui_url}")
            else:
                print(f"  Webapp client: not configured (XSIAM webapp resources will be skipped)")
                print(f"    Provide --session-token or run cortex-login to export XSIAM-specific resources")

        # Test webapp connection
        if webapp_client:
            if webapp_client.test_connection():
                print(f"  Webapp session: valid")
            else:
                print(f"  WARNING: Webapp session test failed (session may be expired)")
                print(f"    XSIAM webapp resources may fail to export")

    print(f"\nExporting configuration...")
    run_export(client, webapp_client, args.output_dir, resource_types, args.save_raw,
               args.url, args.auth_id)


if __name__ == "__main__":
    main()
