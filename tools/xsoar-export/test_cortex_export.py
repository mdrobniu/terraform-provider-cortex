"""Unit tests for cortex_export.py."""

import json
from unittest.mock import MagicMock, patch

import pytest

from cortex_export import (
    PLATFORM_V6,
    PLATFORM_V8_OPP,
    PLATFORM_V8_SAAS,
    PLATFORM_XSIAM,
    PlatformInfo,
    WebappClient,
    XSOARClient,
    derive_ui_url,
    export_credentials,
    export_exclusion_list,
    export_jobs,
    export_marketplace_packs,
    export_password_policy,
    export_server_config,
    grid_bool,
    grid_int,
    grid_json,
    grid_list,
    grid_str,
    hcl_string,
    hcl_value,
    make_unique_ids,
    render_resource,
    sanitize_tf_id,
)


# ===== hcl_string =====

class TestHCLString:
    def test_simple_string(self):
        assert hcl_string("hello") == '"hello"'

    def test_escapes_backslash(self):
        assert hcl_string("a\\b") == '"a\\\\b"'

    def test_escapes_quotes(self):
        assert hcl_string('say "hi"') == '"say \\"hi\\""'

    def test_escapes_newline(self):
        assert hcl_string("line1\nline2") == '"line1\\nline2"'

    def test_empty_string(self):
        assert hcl_string("") == '""'

    def test_combined_escapes(self):
        assert hcl_string('a\\b\n"c"') == '"a\\\\b\\n\\"c\\""'


# ===== hcl_value =====

class TestHCLValue:
    def test_bool_true(self):
        assert hcl_value(True) == "true"

    def test_bool_false(self):
        assert hcl_value(False) == "false"

    def test_bool_before_int(self):
        # bool is subclass of int in Python - must check bool FIRST
        assert hcl_value(True) == "true"
        assert hcl_value(False) == "false"
        # Ensure 1 and 0 are treated as ints, not bools
        assert hcl_value(1) == "1"
        assert hcl_value(0) == "0"

    def test_integer(self):
        assert hcl_value(42) == "42"

    def test_float(self):
        assert hcl_value(3.14) == "3.14"

    def test_string(self):
        assert hcl_value("hello") == '"hello"'

    def test_list(self):
        assert hcl_value(["a", "b"]) == '["a", "b"]'

    def test_empty_list(self):
        assert hcl_value([]) == "[]"

    def test_none(self):
        assert hcl_value(None) == "null"

    def test_dict(self):
        result = hcl_value({"key": "val"})
        assert '"key"' in result
        assert '"val"' in result

    def test_mixed_list(self):
        result = hcl_value([1, "two", True])
        assert "1" in result
        assert '"two"' in result
        assert "true" in result


# ===== sanitize_tf_id =====

class TestSanitizeTFID:
    def test_simple(self):
        assert sanitize_tf_id("my_resource") == "my_resource"

    def test_special_chars(self):
        assert sanitize_tf_id("my-resource.name") == "my_resource_name"

    def test_digit_prefix(self):
        assert sanitize_tf_id("123abc") == "_123abc"

    def test_empty_string(self):
        assert sanitize_tf_id("") == "_unnamed"

    def test_uppercase(self):
        assert sanitize_tf_id("MyResource") == "myresource"

    def test_consecutive_underscores(self):
        assert sanitize_tf_id("a--b__c") == "a_b_c"

    def test_leading_trailing_special(self):
        assert sanitize_tf_id("---hello---") == "hello"

    def test_spaces(self):
        assert sanitize_tf_id("my resource name") == "my_resource_name"


# ===== make_unique_ids =====

class TestMakeUniqueIDs:
    def test_no_collision(self):
        result = make_unique_ids(["alpha", "beta", "gamma"])
        assert result == {"alpha": "alpha", "beta": "beta", "gamma": "gamma"}

    def test_collision_suffixes(self):
        result = make_unique_ids(["a-b", "a.b", "a_b"])
        # All three sanitize to "a_b" -> first gets "a_b", second gets "a_b_1", third gets "a_b_2"
        assert result["a-b"] == "a_b"
        assert result["a.b"] == "a_b_1"
        assert result["a_b"] == "a_b_2"

    def test_sanitized_collision(self):
        result = make_unique_ids(["Test-1", "test.1"])
        assert result["Test-1"] == "test_1"
        assert result["test.1"] == "test_1_1"

    def test_single_item(self):
        result = make_unique_ids(["only"])
        assert result == {"only": "only"}


# ===== render_resource =====

class TestRenderResource:
    def test_basic_output(self):
        result = render_resource("cortex_job", "my_job", {"name": "Test"})
        assert 'resource "cortex_job" "my_job"' in result
        assert 'name = "Test"' in result
        assert result.endswith("}")

    def test_var_unquoted(self):
        result = render_resource("cortex_credential", "cred", {
            "name": "test",
            "password": "var.cred_password",
        })
        assert "password = var.cred_password" in result
        # var. references should NOT be quoted
        assert 'password = "var.' not in result

    def test_comments(self):
        result = render_resource("cortex_job", "j", {"name": "x"},
                                 comments=["This is a comment", "Another"])
        assert "# This is a comment" in result
        assert "# Another" in result


# ===== derive_ui_url =====

class TestDeriveUIURL:
    def test_strip_api_prefix(self):
        assert derive_ui_url("https://api-xsoar8.example.com") == "https://xsoar8.example.com"

    def test_no_api_prefix(self):
        assert derive_ui_url("https://xsoar.example.com") == "https://xsoar.example.com"

    def test_custom_port(self):
        assert derive_ui_url("https://api-xsoar.example.com:8443") == "https://xsoar.example.com:8443"

    def test_standard_ports_omitted(self):
        # Port 443 with https should not appear in output
        assert derive_ui_url("https://api-host.example.com:443") == "https://host.example.com"


# ===== grid helpers =====

class TestGridStr:
    def test_present(self):
        assert grid_str({"NAME": "hello"}, "NAME") == "hello"

    def test_missing(self):
        assert grid_str({}, "NAME") == ""

    def test_none_value(self):
        assert grid_str({"NAME": None}, "NAME") == ""

    def test_numeric_value(self):
        assert grid_str({"NAME": 42}, "NAME") == "42"


class TestGridInt:
    def test_present_int(self):
        assert grid_int({"COUNT": 5}, "COUNT") == 5

    def test_present_float(self):
        assert grid_int({"COUNT": 5.7}, "COUNT") == 5

    def test_missing(self):
        assert grid_int({}, "COUNT") == 0

    def test_string_returns_zero(self):
        assert grid_int({"COUNT": "abc"}, "COUNT") == 0


class TestGridBool:
    def test_true_bool(self):
        assert grid_bool({"ENABLED": True}, "ENABLED") is True

    def test_false_bool(self):
        assert grid_bool({"ENABLED": False}, "ENABLED") is False

    def test_true_string(self):
        assert grid_bool({"ENABLED": "true"}, "ENABLED") is True

    def test_yes_string(self):
        assert grid_bool({"ENABLED": "yes"}, "ENABLED") is True

    def test_missing(self):
        assert grid_bool({}, "ENABLED") is False

    def test_none(self):
        assert grid_bool({"ENABLED": None}, "ENABLED") is False


class TestGridJson:
    def test_dict_value(self):
        result = grid_json({"FILTER": {"AND": []}}, "FILTER")
        parsed = json.loads(result)
        assert parsed == {"AND": []}

    def test_string_value(self):
        assert grid_json({"FILTER": '{"key":"val"}'}, "FILTER") == '{"key":"val"}'

    def test_none_value(self):
        assert grid_json({"FILTER": None}, "FILTER") == ""

    def test_missing(self):
        assert grid_json({}, "FILTER") == ""

    def test_list_value(self):
        result = grid_json({"ITEMS": [1, 2, 3]}, "ITEMS")
        assert json.loads(result) == [1, 2, 3]


class TestGridList:
    def test_present(self):
        assert grid_list({"TAGS": ["a", "b"]}, "TAGS") == ["a", "b"]

    def test_missing(self):
        assert grid_list({}, "TAGS") == []

    def test_non_list(self):
        assert grid_list({"TAGS": "not-a-list"}, "TAGS") == []

    def test_filters_none(self):
        assert grid_list({"TAGS": ["a", None, "b"]}, "TAGS") == ["a", "b"]


# ===== PlatformInfo =====

class TestPlatformInfo:
    def test_v6(self):
        p = PlatformInfo(version="6.14.0", major=6, product_mode="xsoar", deployment_mode="opp")
        assert p.platform == PLATFORM_V6
        assert "XSOAR 6" in p.label
        assert not p.is_v8
        assert not p.is_xsiam

    def test_v8_opp(self):
        p = PlatformInfo(version="8.9.0", major=8, product_mode="xsoar", deployment_mode="opp")
        assert p.platform == PLATFORM_V8_OPP
        assert "XSOAR 8 OPP" in p.label
        assert p.is_v8
        assert not p.is_xsiam

    def test_v8_saas(self):
        p = PlatformInfo(version="8.13.0", major=8, product_mode="xsoar", deployment_mode="saas")
        assert p.platform == PLATFORM_V8_SAAS
        assert "XSOAR 8 SaaS" in p.label
        assert p.is_v8

    def test_xsiam(self):
        p = PlatformInfo(version="8.13.0", major=8, product_mode="xsiam", deployment_mode="saas")
        assert p.platform == PLATFORM_XSIAM
        assert "XSIAM" in p.label
        assert p.is_v8
        assert p.is_xsiam

    def test_label_includes_version(self):
        p = PlatformInfo(version="8.13.0", major=8, product_mode="xsiam", deployment_mode="saas")
        assert "8.13.0" in p.label


# ===== Export Functions (mocked client) =====

class TestExportServerConfig:
    def test_exports_config_keys(self):
        mock_client = MagicMock(spec=XSOARClient)
        mock_client.get.return_value = {
            "sysConf": {
                "versn": 3,
                "server.log.level": "info",
                "content.pack.feedback": "true",
            }
        }
        content, imports, _ = export_server_config(mock_client)
        assert "cortex_server_config" in content
        assert "server.log.level" in content
        # versn should be skipped
        assert "versn" not in content
        assert len(imports) == 2

    def test_handles_api_error(self):
        mock_client = MagicMock(spec=XSOARClient)
        mock_client.get.side_effect = Exception("connection refused")
        content, imports, _ = export_server_config(mock_client)
        assert content == ""
        assert imports == []


class TestExportCredentials:
    def test_exports_credentials(self):
        mock_client = MagicMock(spec=XSOARClient)
        mock_client.post.return_value = {
            "credentials": [
                {"id": "c1", "name": "admin-cred", "user": "admin", "comment": "main"},
                {"id": "c2", "name": "api-cred", "user": "api-user", "comment": ""},
            ]
        }
        content, imports, variables = export_credentials(mock_client)
        assert "cortex_credential" in content
        assert "admin_cred" in content
        assert "api_cred" in content
        # Passwords should be replaced with variables
        assert "var." in content
        assert len(variables) > 0
        assert len(imports) == 2

    def test_handles_empty(self):
        mock_client = MagicMock(spec=XSOARClient)
        mock_client.post.return_value = {"credentials": []}
        content, imports, _ = export_credentials(mock_client)
        assert content == ""


class TestExportJobs:
    def test_exports_basic_job(self):
        mock_client = MagicMock(spec=XSOARClient)
        mock_client.platform = PlatformInfo(version="6.14.0", major=6)
        mock_client.post.return_value = {
            "data": [
                {
                    "id": "j1",
                    "name": "Daily Cleanup",
                    "playbookId": "cleanup-playbook",
                    "type": "Unclassified",
                    "scheduled": True,
                    "cron": "0 0 * * *",
                }
            ]
        }
        content, imports, _ = export_jobs(mock_client)
        assert "cortex_job" in content
        assert "daily_cleanup" in content
        assert "cleanup-playbook" in content
        assert len(imports) == 1

    def test_handles_empty_jobs(self):
        mock_client = MagicMock(spec=XSOARClient)
        mock_client.platform = None
        mock_client.post.return_value = {"data": []}
        content, imports, _ = export_jobs(mock_client)
        assert content == ""


class TestExportMarketplacePacks:
    def test_exports_packs(self):
        mock_client = MagicMock(spec=XSOARClient)
        mock_client.get.return_value = [
            {"id": "Base", "name": "Base", "currentVersion": "1.0.0"},
            {"id": "CommonTypes", "name": "Common Types", "currentVersion": "2.0.0"},
        ]
        content, imports, _ = export_marketplace_packs(mock_client)
        assert "cortex_marketplace_pack" in content
        assert "Base" in content
        assert len(imports) == 2


class TestExportExclusionList:
    def test_exports_exclusions(self):
        mock_client = MagicMock(spec=XSOARClient)
        mock_client.get.return_value = [
            {"id": "e1", "value": "10.0.0.0/8", "type": "CIDR", "reason": "internal"},
            {"id": "e2", "value": "test\\.com", "type": "regex", "reason": "testing"},
        ]
        content, imports, _ = export_exclusion_list(mock_client)
        assert "cortex_exclusion_list" in content
        assert "10.0.0.0/8" in content
        assert len(imports) == 2


class TestExportPasswordPolicy:
    def test_exports_policy(self):
        mock_client = MagicMock(spec=XSOARClient)
        mock_client.get.return_value = {
            "enabled": True,
            "minPasswordLength": 8,
            "minLowercaseChars": 1,
            "minUppercaseChars": 1,
            "minDigitsOrSymbols": 1,
            "preventRepetition": True,
            "expireAfter": 90,
            "maxFailedLoginAttempts": 5,
            "selfUnlockAfterMinutes": 30,
            "version": 1,
        }
        content, imports, _ = export_password_policy(mock_client)
        assert "cortex_password_policy" in content
        assert "min_password_length = 8" in content
        assert "enabled = true" in content
        assert len(imports) == 1


# ===== XSOARClient =====

class TestXSOARClientInit:
    def test_v6_no_prefix(self):
        client = XSOARClient("https://xsoar.example.com", "KEY")
        assert client.prefix == ""
        assert not client.is_v8

    def test_v8_with_prefix(self):
        client = XSOARClient("https://api-xsoar8.example.com", "KEY", auth_id="11")
        assert client.prefix == "/xsoar"
        assert client.is_v8

    def test_trailing_slash_stripped(self):
        client = XSOARClient("https://xsoar.example.com/", "KEY")
        assert client.base_url == "https://xsoar.example.com"


class TestXSOARClientDetectPlatform:
    def test_v6_detection(self):
        client = XSOARClient("https://xsoar.example.com", "KEY")
        with patch.object(client, "get", return_value={
            "demistoVersion": "6.14.0",
        }):
            platform = client.detect_platform()
            assert platform.major == 6
            assert platform.platform == PLATFORM_V6

    def test_xsiam_detection(self):
        client = XSOARClient("https://api.example.com", "KEY", auth_id="413")
        with patch.object(client, "get", return_value={
            "demistoVersion": "8.13.0",
            "productMode": "xsiam",
            "deploymentMode": "saas",
        }):
            platform = client.detect_platform()
            assert platform.major == 8
            assert platform.platform == PLATFORM_XSIAM
            assert platform.is_xsiam


# ===== WebappClient =====

class TestWebappClient:
    def test_session_token_sets_cookies(self):
        wc = WebappClient("https://xsiam.example.com", session_token="my-token")
        cookies = dict(wc.session.cookies)
        assert "app-proxy-hydra-prod-us" in cookies
        assert "app-hub" in cookies

    def test_no_token_no_cookies(self):
        wc = WebappClient("https://xsiam.example.com")
        cookies = dict(wc.session.cookies)
        assert len(cookies) == 0
