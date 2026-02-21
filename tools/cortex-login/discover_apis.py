#!/usr/bin/env python3
"""
discover_apis.py: Crawl XSIAM/XSOAR webapp API endpoints using saved session.

Calls each known endpoint and saves request/response pairs for analysis.

Usage:
    python discover_apis.py [--url URL] [--output-dir /tmp/api_discovery]
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.request
from pathlib import Path
from uuid import uuid4

SESSION_FILE = Path.home() / ".cortex" / "session.json"


def load_session():
    """Load session from ~/.cortex/session.json."""
    if not SESSION_FILE.exists():
        print("No session found. Run: cortex-login --url <URL>")
        sys.exit(1)
    with open(SESSION_FILE) as f:
        return json.load(f)


def make_request(session, method, path, body=None, query_params=None):
    """Make authenticated webapp API request."""
    url = session["url"].rstrip("/") + path
    if query_params:
        url += "?" + "&".join(f"{k}={v}" for k, v in query_params.items())

    data = None
    if body is not None:
        data = json.dumps(body).encode()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    # Build cookie header from all cookies
    cookie_parts = []
    for name, value in session.get("all_cookies", session.get("cookies", {})).items():
        cookie_parts.append(f"{name}={value}")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Cookie": "; ".join(cookie_parts),
        "x-requested-with": "XMLHttpRequest",
        "x-xdr-request-token": str(uuid4()),
    }
    if session.get("xsrf_token"):
        headers["x-xsrf-token"] = session["xsrf_token"]
    if session.get("csrf_token"):
        headers["x-csrf-token"] = session["csrf_token"]

    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=30)
        resp_body = resp.read().decode()
        try:
            resp_json = json.loads(resp_body)
        except json.JSONDecodeError:
            resp_json = resp_body[:1000]
        return {
            "status": resp.status,
            "body": resp_json,
        }
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode()[:500]
        return {
            "status": e.code,
            "error": resp_body,
        }
    except Exception as e:
        return {
            "status": -1,
            "error": str(e),
        }


# Endpoints to discover - organized by feature area
ENDPOINTS = {
    # Correlation Rules
    "correlation_list": {
        "method": "POST",
        "path": "/api/webapp/get_data",
        "params": {"type": "grid", "table_name": "CORRELATION_RULES"},
        "body": {
            "filter_data": {
                "sort": [{"FIELD": "MODIFY_TIME", "ORDER": "DESC"}],
                "filter": {},
                "paging": {"from": 0, "to": 10},
            }
        },
    },
    "correlation_capabilities": {
        "method": "POST",
        "path": "/api/webapp/correlations/get_correlation_capabilities/",
        "body": {"xql_query": "", "execution_mode": "SCHEDULED"},
    },
    "correlation_validate_realtime": {
        "method": "POST",
        "path": "/api/webapp/correlations/validate_realtime",
        "body": {"xql_query": ""},
    },
    "correlation_lookups": {
        "method": "POST",
        "path": "/api/webapp/correlations/get_lookups_with_schema",
        "body": {"filter_sys_fields": True},
    },
    "correlation_view_def": {
        "method": "GET",
        "path": "/api/webapp/get_view_def",
        "params": {"table_name": "CORRELATION_RULES"},
    },

    # IOC Rules
    "ioc_list": {
        "method": "POST",
        "path": "/api/webapp/get_data",
        "params": {"type": "grid", "table_name": "IOC_RULE_TABLE"},
        "body": {
            "filter_data": {
                "sort": [{"FIELD": "RULE_MODIFY_TIME", "ORDER": "DESC"}],
                "filter": {},
                "paging": {"from": 0, "to": 10},
            }
        },
    },
    "ioc_xql_mappings": {
        "method": "POST",
        "path": "/api/webapp/ioc/get_ioc_xql_mappings/",
        "body": {},
    },
    "ioc_ttl": {
        "method": "GET",
        "path": "/api/webapp/ioc/get_ttl/",
    },
    "ioc_view_def": {
        "method": "GET",
        "path": "/api/webapp/get_view_def",
        "params": {"table_name": "IOC_RULE_TABLE"},
    },

    # BIOC Rules
    "bioc_list": {
        "method": "POST",
        "path": "/api/webapp/get_data",
        "params": {"type": "grid", "table_name": "BIOC_RULE_TABLE"},
        "body": {
            "filter_data": {
                "sort": [{"FIELD": "RULE_MODIFY_TIME", "ORDER": "DESC"}],
                "filter": {},
                "paging": {"from": 0, "to": 10},
            }
        },
    },
    "bioc_techniques": {
        "method": "POST",
        "path": "/api/webapp/bioc/get_dynamic_enum_technique/",
        "body": {},
    },
    "bioc_builder": {
        "method": "POST",
        "path": "/api/webapp/open_builder/bioc/",
        "body": {},
    },
    "bioc_view_def": {
        "method": "GET",
        "path": "/api/webapp/get_view_def",
        "params": {"table_name": "BIOC_RULE_TABLE"},
    },

    # Datasets
    "datasets_available": {
        "method": "POST",
        "path": "/api/webapp/xql/get_available_datasets",
        "body": {},
    },
    "datasets_system": {
        "method": "POST",
        "path": "/api/webapp/xql/get_system_datasets",
        "body": {},
    },

    # Incident Domains
    "domains_list": {
        "method": "POST",
        "path": "/api/webapp/incident_domains/get_domains/",
        "body": {},
    },
    "domains_correlations": {
        "method": "POST",
        "path": "/api/webapp/incident_domains/get_correlations_data/",
        "body": {},
    },

    # Version / Health
    "version": {
        "method": "GET",
        "path": "/api/webapp/version/",
    },

    # Session / JWT
    "jwt_info": {
        "method": "GET",
        "path": "/api/jwt/",
    },
    "config": {
        "method": "GET",
        "path": "/api/get_config",
    },

    # Additional tables to discover
    "analytics_detectors": {
        "method": "POST",
        "path": "/api/webapp/get_data",
        "params": {"table_name": "ANALYTICS_DETECTORS_TABLE"},
        "body": {"filter_data": {"paging": {"from": 0, "to": 5}}},
    },

    # Playbook rules
    "playbook_suggestion_rules": {
        "method": "POST",
        "path": "/api/webapp/get_data",
        "params": {"type": "grid", "table_name": "PLAYBOOK_SUGGESTION_RULES_TABLE", "data_id": "null"},
        "body": {"filter_data": {"sort": [], "filter": {}, "paging": {"from": 0, "to": 5}}},
    },
}


def discover(session, output_dir, endpoints=None):
    """Run all endpoint discoveries."""
    os.makedirs(output_dir, exist_ok=True)

    targets = endpoints or ENDPOINTS.keys()
    results = {}

    for name in targets:
        if name not in ENDPOINTS:
            print(f"  Unknown endpoint: {name}")
            continue

        ep = ENDPOINTS[name]
        method = ep["method"]
        path = ep["path"]
        body = ep.get("body")
        params = ep.get("params")

        print(f"  {name}: {method} {path}", end="")
        if params:
            print(f"?{'&'.join(f'{k}={v}' for k, v in params.items())}", end="")
        print(" ... ", end="", flush=True)

        result = make_request(session, method, path, body=body, query_params=params)
        status = result.get("status", -1)
        print(f"{status}")

        results[name] = {
            "endpoint": f"{method} {path}",
            "params": params,
            "request_body": body,
            "status": status,
            "response": result.get("body") or result.get("error"),
        }

        # Save individual response
        with open(os.path.join(output_dir, f"{name}.json"), "w") as f:
            json.dump(results[name], f, indent=2, default=str)

        time.sleep(0.2)  # Rate limiting

    # Save summary
    summary = {name: {"status": r["status"], "endpoint": r["endpoint"]} for name, r in results.items()}
    with open(os.path.join(output_dir, "_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nResults saved to {output_dir}/")
    print(f"Summary: {sum(1 for r in results.values() if r['status'] == 200)}/{len(results)} successful")

    return results


def main():
    parser = argparse.ArgumentParser(description="Discover XSIAM/XSOAR webapp API endpoints")
    parser.add_argument("--url", help="Override URL from session")
    parser.add_argument("--output-dir", default="/tmp/api_discovery",
                        help="Output directory (default: /tmp/api_discovery)")
    parser.add_argument("--endpoints", nargs="*",
                        help=f"Specific endpoints to test (default: all). Available: {', '.join(ENDPOINTS.keys())}")

    args = parser.parse_args()

    session = load_session()
    if args.url:
        session["url"] = args.url.rstrip("/")

    print(f"Discovering APIs on: {session['url']}")
    print()

    discover(session, args.output_dir, args.endpoints)


if __name__ == "__main__":
    main()
