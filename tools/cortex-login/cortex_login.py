#!/usr/bin/env python3
"""
cortex-login: SSO login tool for Cortex XSIAM and XSOAR 8 SaaS.

Opens a browser for SSO authentication, captures session cookies and tokens,
and saves them to ~/.cortex/session.json for use by the Terraform provider.

Usage:
    cortex-login --url https://mytenant.xdr.us.paloaltonetworks.com
    cortex-login --url https://myxsoar.crtx.us.paloaltonetworks.com
    cortex-login --headless  # paste cookies from browser DevTools
    cortex-login --status    # check session validity
    cortex-login --logout    # clear saved session
    cortex-login --cookies   # print saved cookies for debugging

Install:
    pip install playwright
    playwright install chromium
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

SESSION_DIR = Path.home() / ".cortex"
SESSION_FILE = SESSION_DIR / "session.json"


def get_session_path():
    """Return path to session file, creating directory if needed."""
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    return SESSION_FILE


def save_session(session_data):
    """Save session data to ~/.cortex/session.json."""
    path = get_session_path()
    with open(path, "w") as f:
        json.dump(session_data, f, indent=2)
    os.chmod(path, 0o600)  # readable only by owner
    print(f"Session saved to {path}")


def load_session():
    """Load session data from ~/.cortex/session.json."""
    path = get_session_path()
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def browser_login(url, timeout_seconds=300):
    """Open browser for SSO login and capture session cookies/tokens."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Error: playwright not installed. Run: pip install playwright && playwright install chromium")
        sys.exit(1)

    url = url.rstrip("/")
    print(f"Opening browser for SSO login to: {url}")
    print(f"Complete the login in the browser window. Timeout: {timeout_seconds}s")
    print()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # Navigate to the instance URL - will redirect to SSO
        page.goto(url, wait_until="domcontentloaded")

        # Wait for login to complete - detected by:
        # 1. URL returning to the instance (not SSO/Okta)
        # 2. Or specific API calls being made
        print("Waiting for SSO login to complete...")

        session_data = None
        start_time = time.time()

        while time.time() - start_time < timeout_seconds:
            current_url = page.url
            # After SSO, user is redirected back to the instance
            if url.split("//")[1].split("/")[0] in current_url and "/idp/" not in current_url:
                # Check if session cookies are set
                cookies = context.cookies()
                cookie_dict = {c["name"]: c for c in cookies}

                # Look for session indicators
                has_session = any(
                    name in cookie_dict
                    for name in ["app-proxy-hydra-prod-us", "app-hub", "XSRF-TOKEN", "csrf_token"]
                )

                if has_session:
                    # Try to get JWT info
                    jwt_data = None
                    try:
                        resp = page.evaluate("""
                            async () => {
                                try {
                                    const r = await fetch('/api/jwt/', {credentials: 'include'});
                                    return await r.json();
                                } catch(e) {
                                    return null;
                                }
                            }
                        """)
                        jwt_data = resp
                    except Exception:
                        pass

                    # Try to get XSRF token from cookie or page context
                    xsrf_token = None
                    csrf_token = None

                    if "XSRF-TOKEN" in cookie_dict:
                        xsrf_token = cookie_dict["XSRF-TOKEN"]["value"]
                    if "csrf_token" in cookie_dict:
                        csrf_token = cookie_dict["csrf_token"]["value"]

                    # If XSRF not in cookies, try to extract from page
                    if not xsrf_token:
                        try:
                            xsrf_token = page.evaluate("""
                                () => {
                                    const cookies = document.cookie.split(';');
                                    for (const c of cookies) {
                                        const [name, ...val] = c.trim().split('=');
                                        if (name === 'XSRF-TOKEN') return val.join('=');
                                    }
                                    return null;
                                }
                            """)
                        except Exception:
                            pass

                    # Build session data
                    session_cookies = {}
                    for name in ["app-proxy-hydra-prod-us", "app-hub"]:
                        if name in cookie_dict:
                            session_cookies[name] = cookie_dict[name]["value"]

                    # Get all cookies for this domain
                    all_cookies = {c["name"]: c["value"] for c in cookies
                                   if url.split("//")[1].split("/")[0] in c.get("domain", "")}

                    session_data = {
                        "url": url,
                        "cookies": session_cookies,
                        "all_cookies": all_cookies,
                        "xsrf_token": f"Bearer {xsrf_token}" if xsrf_token and not xsrf_token.startswith("Bearer ") else xsrf_token,
                        "csrf_token": csrf_token,
                        "jwt_info": jwt_data,
                        "login_time": int(time.time()),
                        "expiry": jwt_data.get("expiry") if jwt_data else int(time.time()) + 28800,  # 8h default
                    }

                    # Detect product mode
                    try:
                        about_resp = page.evaluate("""
                            async () => {
                                try {
                                    const r = await fetch('/xsoar/about', {
                                        credentials: 'include',
                                        headers: {'x-platform-module-name': 'xsoar'}
                                    });
                                    return await r.json();
                                } catch(e) {
                                    return null;
                                }
                            }
                        """)
                        if about_resp:
                            session_data["product_mode"] = about_resp.get("productMode", "xsoar")
                            session_data["deployment_mode"] = about_resp.get("deploymentMode", "")
                            session_data["version"] = about_resp.get("demistoVersion", "")
                    except Exception:
                        pass

                    print(f"\nLogin successful!")
                    if jwt_data:
                        print(f"  User: {jwt_data.get('email', 'unknown')}")
                        print(f"  Role: {jwt_data.get('default_role', 'unknown')}")
                        exp = jwt_data.get("expiry", 0)
                        remaining = exp - int(time.time())
                        print(f"  Expires in: {remaining // 3600}h {(remaining % 3600) // 60}m")
                    print(f"  Cookies captured: {len(session_cookies)}")
                    print(f"  XSRF token: {'yes' if xsrf_token else 'no'}")
                    print(f"  CSRF token: {'yes' if csrf_token else 'no'}")

                    break

            time.sleep(1)

        browser.close()

        if not session_data:
            print("\nLogin timed out or failed. No session cookies captured.")
            sys.exit(1)

        return session_data


def headless_login(url):
    """Manual cookie entry for headless/SSH environments."""
    url = url.rstrip("/")
    print(f"Headless login mode for: {url}")
    print()
    print("To get cookies from your browser:")
    print("  1. Log into the Cortex instance in your browser")
    print("  2. Open DevTools (F12) -> Application -> Cookies")
    print("  3. Copy the values below")
    print()

    cookies = {}

    # Required session cookies
    for name in ["app-proxy-hydra-prod-us", "app-hub"]:
        val = input(f"  {name} cookie value (or press Enter to skip): ").strip()
        if val:
            cookies[name] = val

    if not cookies:
        print("\nNo cookies provided. You can also paste all cookies as JSON:")
        raw = input("  Paste JSON cookies dict (or press Enter to abort): ").strip()
        if raw:
            try:
                cookies = json.loads(raw)
            except json.JSONDecodeError:
                print("Invalid JSON. Aborting.")
                sys.exit(1)
        else:
            print("Aborting.")
            sys.exit(1)

    # Optional tokens
    xsrf = input("\n  XSRF-TOKEN cookie value (or press Enter to skip): ").strip()
    csrf = input("  csrf_token cookie value (or press Enter to skip): ").strip()

    session_data = {
        "url": url,
        "cookies": cookies,
        "all_cookies": cookies.copy(),
        "xsrf_token": f"Bearer {xsrf}" if xsrf and not xsrf.startswith("Bearer ") else xsrf or None,
        "csrf_token": csrf or None,
        "jwt_info": None,
        "login_time": int(time.time()),
        "expiry": int(time.time()) + 28800,  # 8h default
    }

    print(f"\nSession configured with {len(cookies)} cookies.")
    return session_data


def check_status():
    """Check status of saved session."""
    session = load_session()
    if not session:
        print("No session found. Run: cortex-login --url <URL>")
        return False

    url = session.get("url", "unknown")
    expiry = session.get("expiry", 0)
    now = int(time.time())
    remaining = expiry - now
    cookies = session.get("cookies", {})
    product = session.get("product_mode", "unknown")

    print(f"Session for: {url}")
    print(f"  Product: {product}")
    print(f"  Cookies: {len(cookies)}")
    print(f"  XSRF token: {'yes' if session.get('xsrf_token') else 'no'}")
    print(f"  CSRF token: {'yes' if session.get('csrf_token') else 'no'}")

    if session.get("jwt_info"):
        print(f"  User: {session['jwt_info'].get('email', 'unknown')}")
        print(f"  Role: {session['jwt_info'].get('default_role', 'unknown')}")

    if remaining > 0:
        print(f"  Status: ACTIVE (expires in {remaining // 3600}h {(remaining % 3600) // 60}m)")
        return True
    else:
        print(f"  Status: EXPIRED ({abs(remaining) // 3600}h {(abs(remaining) % 3600) // 60}m ago)")
        return False


def show_cookies():
    """Print saved cookies for debugging."""
    session = load_session()
    if not session:
        print("No session found.")
        return

    print(json.dumps(session, indent=2, default=str))


def refresh_session(url=None):
    """Attempt to refresh the session using session-extension endpoint."""
    session = load_session()
    if not session:
        print("No session found. Run: cortex-login --url <URL>")
        sys.exit(1)

    import urllib.request
    import ssl

    target_url = url or session.get("url", "")
    if not target_url:
        print("No URL found in session. Provide --url.")
        sys.exit(1)

    # Build cookie header
    cookie_parts = []
    for name, value in session.get("cookies", {}).items():
        cookie_parts.append(f"{name}={value}")
    for name, value in session.get("all_cookies", {}).items():
        if name not in session.get("cookies", {}):
            cookie_parts.append(f"{name}={value}")

    cookie_header = "; ".join(cookie_parts)

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            f"{target_url}/session-extension",
            headers={
                "Cookie": cookie_header,
                "x-requested-with": "XMLHttpRequest",
            },
        )
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        body = resp.read().decode()
        print(f"Session extension response: {body}")

        if "refreshed" in body:
            session["expiry"] = int(time.time()) + 28800
            save_session(session)
            print("Session refreshed successfully.")
        else:
            print("Session extension returned unexpected response.")
    except Exception as e:
        print(f"Session refresh failed: {e}")
        print("You may need to re-login: cortex-login --url <URL>")


def logout():
    """Clear saved session."""
    path = get_session_path()
    if path.exists():
        path.unlink()
        print("Session cleared.")
    else:
        print("No session found.")


def main():
    parser = argparse.ArgumentParser(
        description="SSO login tool for Cortex XSIAM and XSOAR 8 SaaS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cortex-login --url https://mytenant.xdr.us.paloaltonetworks.com
  cortex-login --url https://myxsoar.crtx.us.paloaltonetworks.com --headless
  cortex-login --status
  cortex-login --refresh
  cortex-login --logout
  cortex-login --cookies
""",
    )

    parser.add_argument("--url", help="URL of the Cortex instance (UI URL)")
    parser.add_argument("--headless", action="store_true",
                        help="Manual cookie entry mode (for SSH/remote servers)")
    parser.add_argument("--status", action="store_true",
                        help="Check saved session status")
    parser.add_argument("--refresh", action="store_true",
                        help="Attempt to refresh the session")
    parser.add_argument("--logout", action="store_true",
                        help="Clear saved session")
    parser.add_argument("--cookies", action="store_true",
                        help="Print saved cookies as JSON")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Login timeout in seconds (default: 300)")

    args = parser.parse_args()

    if args.status:
        sys.exit(0 if check_status() else 1)
    elif args.logout:
        logout()
    elif args.cookies:
        show_cookies()
    elif args.refresh:
        refresh_session(args.url)
    elif args.url:
        if args.headless:
            session = headless_login(args.url)
        else:
            session = browser_login(args.url, timeout_seconds=args.timeout)
        save_session(session)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
