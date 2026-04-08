"""
Tests pour le support de la configuration Claude Code
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import patch

from mcp_audit.config import (
    MCPConfig,
    detect_config_format,
    parse_claude_code_config,
    find_default_config,
)
from mcp_audit.audit import MCPAudit


class TestDetectConfigFormat:
    """Tests pour la detection automatique du format."""

    def test_detect_claude_code_format(self):
        data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"]
                }
            }
        }
        assert detect_config_format(data) == 'claude_code'

    def test_detect_native_format_servers(self):
        data = {"servers": {"test": {"command": "python"}}}
        assert detect_config_format(data) == 'native'

    def test_detect_native_format_tools(self):
        data = {"tools": {"test": {"uri": "https://example.com"}}}
        assert detect_config_format(data) == 'native'

    def test_detect_native_format_resources(self):
        data = {"resources": {"test": {"uri": "file:///tmp"}}}
        assert detect_config_format(data) == 'native'

    def test_detect_unknown_format(self):
        data = {"foo": "bar"}
        assert detect_config_format(data) == 'unknown'

    def test_claude_code_has_priority_over_native(self):
        """Si mcpServers ET servers sont presents, mcpServers gagne."""
        data = {
            "mcpServers": {"s1": {"command": "npx"}},
            "servers": {"s2": {"command": "python"}},
        }
        assert detect_config_format(data) == 'claude_code'


class TestParseClaudeCodeConfig:
    """Tests pour le parsing du format Claude Code."""

    def test_parse_stdio_server(self):
        data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {"HOME": "/home/user"},
                }
            }
        }
        servers = parse_claude_code_config(data)
        assert 'filesystem' in servers
        assert servers['filesystem']['_type'] == 'stdio'
        assert servers['filesystem']['_source'] == 'npx'
        assert servers['filesystem']['command'] == 'npx'
        assert servers['filesystem']['args'] == ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]

    def test_parse_http_server(self):
        data = {
            "mcpServers": {
                "context7": {
                    "type": "http",
                    "url": "https://mcp.context7.com/mcp",
                    "headers": {"API_KEY": "${CONTEXT7_API_KEY}"},
                }
            }
        }
        servers = parse_claude_code_config(data)
        assert 'context7' in servers
        assert servers['context7']['_type'] == 'http'
        assert servers['context7']['_source'] == 'https://mcp.context7.com/mcp'

    def test_parse_multiple_servers(self):
        data = {
            "mcpServers": {
                "brave_search": {
                    "command": "npx",
                    "args": ["-y", "@brave/brave-search-mcp-server"],
                },
                "context7": {
                    "type": "http",
                    "url": "https://mcp.context7.com/mcp",
                },
            }
        }
        servers = parse_claude_code_config(data)
        assert len(servers) == 2
        assert 'brave_search' in servers
        assert 'context7' in servers

    def test_parse_empty_mcp_servers(self):
        data = {"mcpServers": {}}
        servers = parse_claude_code_config(data)
        assert servers == {}


class TestMCPConfigLoadClaudeCode:
    """Tests pour le chargement d'une config Claude Code via MCPConfig.load."""

    def test_load_claude_code_settings_json(self):
        """Simule ~/.claude/settings.json avec mcpServers."""
        config_data = {
            "permissions": {"allow": ["*"]},
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                    "env": {},
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
                },
            },
        }

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = MCPConfig.load(temp_path)
            assert config.source_format == 'claude_code'
            assert len(config.servers) == 2
            assert 'filesystem' in config.servers
            assert 'github' in config.servers
            assert config.servers['filesystem']['_type'] == 'stdio'
            assert config.tools == {}
            assert config.resources == {}
        finally:
            temp_path.unlink()

    def test_load_mcp_json_project(self):
        """Simule .mcp.json projet avec http et stdio."""
        config_data = {
            "mcpServers": {
                "api-server": {
                    "type": "http",
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer ${API_KEY}"},
                },
            },
        }

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = MCPConfig.load(temp_path)
            assert config.source_format == 'claude_code'
            assert len(config.servers) == 1
            assert config.servers['api-server']['_type'] == 'http'
        finally:
            temp_path.unlink()

    def test_load_native_still_works(self):
        """Le format natif continue de fonctionner."""
        config_data = {
            "servers": {"s1": {"command": "python -m server"}},
            "tools": {"t1": {"uri": "https://example.com"}},
        }

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = MCPConfig.load(temp_path)
            assert config.source_format == 'native'
            assert 's1' in config.servers
            assert 't1' in config.tools
        finally:
            temp_path.unlink()


class TestClaudeCodeAudit:
    """Tests de l'audit complet avec une config Claude Code."""

    def test_extract_claude_code_dependencies(self):
        config_data = {
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                },
                "context7": {
                    "type": "http",
                    "url": "https://mcp.context7.com/mcp",
                },
            },
        }

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = MCPConfig.load(temp_path)
            auditor = MCPAudit(config, verbose=False)
            deps = auditor._extract_dependencies()

            assert len(deps) == 2
            names = [d.name for d in deps]
            assert 'filesystem' in names
            assert 'context7' in names

            # Verifier les metadonnees
            fs_dep = next(d for d in deps if d.name == 'filesystem')
            assert fs_dep.type == 'server'
            assert fs_dep.metadata['server_type'] == 'stdio'
            assert fs_dep.source == 'npx'

            ctx_dep = next(d for d in deps if d.name == 'context7')
            assert ctx_dep.metadata['server_type'] == 'http'
            assert ctx_dep.source == 'https://mcp.context7.com/mcp'
        finally:
            temp_path.unlink()

    def test_full_audit_claude_code(self):
        config_data = {
            "mcpServers": {
                "test-server": {
                    "command": "npx",
                    "args": ["-y", "some-mcp-server"],
                    "env": {},
                },
            },
        }

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = MCPConfig.load(temp_path)
            auditor = MCPAudit(config, verbose=False)
            results = auditor.audit()

            assert 'summary' in results
            assert 'dependencies' in results
            assert results['summary']['total_dependencies'] == 1
            assert results['summary']['servers'] == 1
            assert results['dependencies'][0]['name'] == 'test-server'
        finally:
            temp_path.unlink()

    def test_quality_score_stdio_with_command(self):
        """Un serveur stdio avec command et args devrait avoir un bon score."""
        config_data = {
            "mcpServers": {
                "full-server": {
                    "command": "npx",
                    "args": ["-y", "@scope/server"],
                    "env": {"KEY": "val"},
                },
            },
        }

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = MCPConfig.load(temp_path)
            auditor = MCPAudit(config, verbose=False)
            results = auditor.audit()

            dep = results['dependencies'][0]
            # command + args presents -> high score (no -5 for missing args)
            assert dep['quality_score'] >= 85
        finally:
            temp_path.unlink()

    def test_quality_score_http_no_headers(self):
        """Un serveur HTTP sans headers devrait avoir un malus."""
        config_data = {
            "mcpServers": {
                "no-auth-server": {
                    "type": "http",
                    "url": "https://example.com/mcp",
                },
            },
        }

        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            json.dump(config_data, f)
            temp_path = Path(f.name)

        try:
            config = MCPConfig.load(temp_path)
            auditor = MCPAudit(config, verbose=False)
            results = auditor.audit()

            dep = results['dependencies'][0]
            # URL ok mais pas de headers -> -10
            assert dep['quality_score'] < 100
            assert dep['quality_score'] >= 80  # pas trop bas non plus
        finally:
            temp_path.unlink()


class TestFindDefaultConfig:
    """Tests pour la detection automatique du chemin de config."""

    def test_finds_existing_file(self, tmp_path):
        """Si un fichier existe dans les chemins candidats, il est retourne."""
        config_file = tmp_path / "settings.json"
        config_file.write_text('{"mcpServers": {}}')

        with patch('mcp_audit.config.Path.home', return_value=tmp_path):
            with patch('mcp_audit.config.Path.cwd', return_value=tmp_path):
                # Creer le repertoire .claude/
                claude_dir = tmp_path / '.claude'
                claude_dir.mkdir(exist_ok=True)
                settings = claude_dir / 'settings.json'
                settings.write_text('{"mcpServers": {}}')

                result = find_default_config()
                assert result is not None

    def test_returns_none_when_nothing_exists(self, tmp_path):
        """Si aucun fichier n'existe, retourne None."""
        with patch('mcp_audit.config.Path.home', return_value=tmp_path):
            with patch('mcp_audit.config.Path.cwd', return_value=tmp_path):
                result = find_default_config()
                assert result is None
