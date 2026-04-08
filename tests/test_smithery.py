"""
Tests for the Smithery registry integration (mcp_audit.smithery).
"""

import pytest
from unittest.mock import patch, MagicMock
from mcp_audit.smithery import (
    is_smithery_source,
    extract_qualified_name,
    fetch_server_info,
    search_servers,
    compute_smithery_bonus,
    _normalize_server,
    _normalize_summary,
)


# ── is_smithery_source ────────────────────────────────────────

class TestIsSmitherySource:
    def test_smithery_prefix(self):
        assert is_smithery_source("smithery:owner/server") is True

    def test_smithery_cli_in_command(self):
        assert is_smithery_source(None, {"command": "npx", "args": ["@smithery/cli", "install"]}) is True

    def test_smithery_cli_in_args(self):
        meta = {"command": "npx", "args": ["-y", "@smithery/cli", "run", "@owner/server"]}
        assert is_smithery_source(None, meta) is True

    def test_smithery_marker(self):
        assert is_smithery_source(None, {"_registry": "smithery"}) is True

    def test_not_smithery_npm(self):
        assert is_smithery_source("npm:express") is False

    def test_not_smithery_github(self):
        assert is_smithery_source("https://github.com/owner/repo") is False

    def test_not_smithery_empty(self):
        assert is_smithery_source(None, None) is False

    def test_not_smithery_plain_source(self):
        assert is_smithery_source("uvx") is False

    def test_smithery_cli_in_command_string(self):
        assert is_smithery_source(None, {"command": "@smithery/cli"}) is True


# ── extract_qualified_name ────────────────────────────────────

class TestExtractQualifiedName:
    def test_smithery_prefix(self):
        assert extract_qualified_name("smithery:owner/server") == "owner/server"

    def test_smithery_prefix_with_at(self):
        assert extract_qualified_name("smithery:@owner/server") == "owner/server"

    def test_from_metadata_args(self):
        meta = {"args": ["-y", "@owner/server"]}
        assert extract_qualified_name(None, meta) == "owner/server"

    def test_from_metadata_args_with_version(self):
        meta = {"args": ["@owner/server@1.0.0"]}
        result = extract_qualified_name(None, meta)
        assert result is not None and result.startswith("owner/server")

    def test_from_source_qualified(self):
        assert extract_qualified_name("owner/server") == "owner/server"

    def test_none_input(self):
        assert extract_qualified_name(None, None) is None

    def test_no_slash(self):
        assert extract_qualified_name("just-a-name") is None


# ── fetch_server_info ─────────────────────────────────────────

class TestFetchServerInfo:
    @patch("mcp_audit.smithery.requests.get")
    def test_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "qualifiedName": "owner/server",
            "displayName": "Test Server",
            "description": "A test",
            "remote": True,
            "security": {"scanPassed": True},
            "tools": [{"name": "tool1"}],
            "resources": [],
            "prompts": None,
            "connections": [{"type": "stdio", "configSchema": {}}],
        }
        mock_get.return_value = mock_resp

        result = fetch_server_info("owner/server")
        assert result is not None
        assert result["qualified_name"] == "owner/server"
        assert result["display_name"] == "Test Server"
        assert result["security_scan_passed"] is True
        assert result["tools_count"] == 1
        assert result["is_smithery"] is True

    @patch("mcp_audit.smithery.requests.get")
    def test_not_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp
        assert fetch_server_info("nonexistent/server") is None

    @patch("mcp_audit.smithery.requests.get")
    def test_network_error(self, mock_get):
        mock_get.side_effect = Exception("timeout")
        assert fetch_server_info("owner/server") is None

    def test_empty_qualified_name(self):
        assert fetch_server_info("") is None

    def test_no_slash(self):
        assert fetch_server_info("noslash") is None


# ── search_servers ─────────────────────────────────────────────

class TestSearchServers:
    @patch("mcp_audit.smithery.requests.get")
    def test_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "servers": [
                {"qualifiedName": "a/b", "displayName": "B", "description": "d", "useCount": 5, "remote": True}
            ],
            "pagination": {"currentPage": 1, "pageSize": 10},
        }
        mock_get.return_value = mock_resp

        result = search_servers("test query")
        assert len(result["servers"]) == 1
        assert result["servers"][0]["qualified_name"] == "a/b"

    @patch("mcp_audit.smithery.requests.get")
    def test_failure(self, mock_get):
        mock_get.side_effect = Exception("fail")
        result = search_servers("test")
        assert result["servers"] == []


# ── compute_smithery_bonus ────────────────────────────────────

class TestComputeSmitheryBonus:
    def test_none_input(self):
        bonus = compute_smithery_bonus(None)
        assert bonus["security_scan_bonus"] == 0
        assert bonus["popularity_bonus"] == 0

    def test_security_scan_passed(self):
        info = {"security_scan_passed": True, "tools_count": 0, "resources_count": 0}
        bonus = compute_smithery_bonus(info)
        assert bonus["security_scan_bonus"] == 5

    def test_security_scan_failed(self):
        info = {"security_scan_passed": False, "tools_count": 0, "resources_count": 0}
        bonus = compute_smithery_bonus(info)
        assert bonus["security_scan_bonus"] == 0

    def test_popular_server(self):
        info = {"security_scan_passed": True, "tools_count": 12, "resources_count": 3}
        bonus = compute_smithery_bonus(info)
        assert bonus["popularity_bonus"] == 3
        assert bonus["tooling_bonus"] == 2

    def test_medium_tools(self):
        info = {"security_scan_passed": None, "tools_count": 5, "resources_count": 0}
        bonus = compute_smithery_bonus(info)
        assert bonus["popularity_bonus"] == 1

    def test_total_bonus_capped(self):
        """Max bonus should not exceed ~10 (5+3+2)."""
        info = {"security_scan_passed": True, "tools_count": 15, "resources_count": 5}
        bonus = compute_smithery_bonus(info)
        total = sum(v for v in bonus.values())
        assert total == 10


# ── _normalize helpers ─────────────────────────────────────────

class TestNormalize:
    def test_normalize_server(self):
        raw = {
            "qualifiedName": "ns/srv",
            "displayName": "Srv",
            "description": "desc",
            "remote": False,
            "security": {"scanPassed": False},
            "tools": [{"name": "t"}, {"name": "t2"}],
            "resources": None,
            "prompts": [],
            "connections": [],
        }
        result = _normalize_server(raw)
        assert result["tools_count"] == 2
        assert result["resources_count"] == 0
        assert result["is_smithery"] is True

    def test_normalize_summary(self):
        raw = {"qualifiedName": "a/b", "displayName": "AB", "description": "x", "useCount": 42, "remote": True}
        result = _normalize_summary(raw)
        assert result["use_count"] == 42


# ── Integration: audit with Smithery ──────────────────────────

class TestSmitheryAuditIntegration:
    """Test that Smithery enrichment works end-to-end in MCPAudit."""

    @patch("mcp_audit.audit.fetch_server_info")
    def test_smithery_enrichment_in_audit(self, mock_fetch):
        """A dependency with smithery: prefix should get enriched."""
        from mcp_audit.config import MCPConfig
        from mcp_audit.audit import MCPAudit
        import tempfile, json

        mock_fetch.return_value = {
            "qualified_name": "owner/test-server",
            "display_name": "Test Server",
            "description": "A Smithery test server",
            "remote": True,
            "transport": "stdio",
            "security_scan_passed": True,
            "tools_count": 5,
            "resources_count": 2,
            "prompts_count": 1,
            "is_smithery": True,
        }

        config_data = {
            "servers": {
                "my-smithery-srv": {
                    "command": "npx",
                    "args": ["-y", "@smithery/cli", "run", "@owner/test-server"],
                }
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name

        try:
            config = MCPConfig.load(config_path)
            audit = MCPAudit(config)
            results = audit.audit()

            # Should have one dependency
            assert len(results["dependencies"]) == 1
            dep = results["dependencies"][0]

            # Should have smithery enrichment
            assert "smithery" in dep
            assert dep["smithery"]["resolved"] is True
            assert dep["smithery"]["display_name"] == "Test Server"
            assert dep["smithery"]["tools_count"] == 5

            # Trust score should include smithery bonus
            assert "smithery_bonus" in dep["trust_score"]
            assert dep["trust_score"]["smithery_bonus"] > 0

            # Summary should count smithery servers
            assert results["summary"]["smithery_servers"] == 1
        finally:
            import os
            os.unlink(config_path)

    def test_non_smithery_dependency_untouched(self):
        """A regular npm dependency should NOT trigger Smithery lookup."""
        from mcp_audit.config import MCPConfig
        from mcp_audit.audit import MCPAudit
        import tempfile, json

        config_data = {
            "servers": {
                "my-regular-srv": {
                    "command": "npx",
                    "args": ["-y", "some-npm-package"],
                }
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name

        try:
            config = MCPConfig.load(config_path)
            audit = MCPAudit(config)
            results = audit.audit()

            dep = results["dependencies"][0]
            assert "smithery" not in dep or dep.get("smithery") is None
            assert results["summary"]["smithery_servers"] == 0
        finally:
            import os
            os.unlink(config_path)

    @patch("mcp_audit.audit.fetch_server_info")
    def test_smithery_source_prefix_detected(self, mock_fetch):
        """A dependency with 'smithery:' source prefix should be detected."""
        from mcp_audit.config import MCPConfig
        from mcp_audit.audit import MCPAudit
        import tempfile, json

        mock_fetch.return_value = {
            "qualified_name": "acme/tools",
            "display_name": "Acme Tools",
            "description": "desc",
            "remote": False,
            "transport": "stdio",
            "security_scan_passed": False,
            "tools_count": 1,
            "resources_count": 0,
            "prompts_count": 0,
            "is_smithery": True,
        }

        # Using native format with source override via command
        config_data = {
            "servers": {
                "acme-tools": {
                    "command": "smithery:acme/tools",
                    "args": [],
                }
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            config_path = f.name

        try:
            config = MCPConfig.load(config_path)
            audit = MCPAudit(config)
            results = audit.audit()

            dep = results["dependencies"][0]
            assert "smithery" in dep
            assert dep["smithery"]["resolved"] is True
        finally:
            import os
            os.unlink(config_path)
