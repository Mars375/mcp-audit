"""
Tests pour le module de configuration
"""

import pytest
import tempfile
import json
from pathlib import Path
from mcp_audit.config import MCPConfig, MCPDependency


class TestMCPConfig:
    
    def test_load_valid_config(self):
        """Test le chargement d'une configuration valide."""
        config_data = {
            "servers": {
                "test-server": {
                    "command": "python -m server",
                    "args": []
                }
            },
            "tools": {
                "test-tool": {
                    "name": "Test Tool",
                    "uri": "https://example.com/tool.py"
                }
            },
            "resources": {
                "test-resource": {
                    "uri": "https://example.com/data.json"
                }
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = Path(f.name)
        
        try:
            config = MCPConfig.load(temp_path)
            assert config.get_server_names() == ["test-server"]
            assert config.get_tool_names() == ["test-tool"]
            assert config.get_resource_names() == ["test-resource"]
        finally:
            temp_path.unlink()
    
    def test_load_nonexistent_file(self):
        """Test le chargement d'un fichier non existant."""
        with pytest.raises(FileNotFoundError):
            MCPConfig.load(Path("/nonexistent/config.json"))
    
    def test_load_invalid_json(self):
        """Test le chargement d'un JSON invalide."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content")
            temp_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError):
                MCPConfig.load(temp_path)
        finally:
            temp_path.unlink()
    
    def test_get_server_config(self):
        """Test la récupération de configuration de serveur."""
        config = MCPConfig()
        config.servers = {"test-server": {"command": "python -m server"}}
        
        server_config = config.get_server_config("test-server")
        assert server_config == {"command": "python -m server"}
        
        nonexistent_config = config.get_server_config("nonexistent")
        assert nonexistent_config is None


class TestMCPDependency:
    
    def test_dependency_creation(self):
        """Test la création d'une dépendance."""
        dep = MCPDependency(
            name="test-tool",
            version="1.0.0",
            type="tool",
            source="https://example.com/tool.py"
        )
        
        assert dep.name == "test-tool"
        assert dep.version == "1.0.0"
        assert dep.type == "tool"
        assert dep.source == "https://example.com/tool.py"
        assert dep.metadata == {}
    
    def test_dependency_with_metadata(self):
        """Test la création d'une dépendance avec métadonnées."""
        metadata = {
            "description": "Test tool",
            "author": "Test Author"
        }
        
        dep = MCPDependency(
            name="test-tool",
            type="tool",
            metadata=metadata
        )
        
        assert dep.metadata == metadata