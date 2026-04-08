"""
Gestion de la configuration MCP

Supporte deux formats :
  1. Format natif mcp-audit : { "servers": {...}, "tools": {...}, "resources": {...} }
  2. Format Claude Code / .mcp.json : { "mcpServers": { "name": { "command"|"url", ... } } }
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


def _claude_code_config_paths() -> List[Path]:
    """Chemins de config Claude Code, evalues a chaque appel."""
    return [
        Path.home() / '.claude' / 'settings.json',
        Path.home() / '.claude.json',
        Path.cwd() / '.mcp.json',
    ]


def detect_config_format(data: Dict[str, Any]) -> str:
    """Detecte le format d'une config MCP.

    Returns:
        'native' pour le format mcp-audit
        'claude_code' pour le format mcpServers
        'unknown' si aucun format reconnu
    """
    if 'mcpServers' in data:
        return 'claude_code'
    if 'servers' in data or 'tools' in data or 'resources' in data:
        return 'native'
    return 'unknown'


def parse_claude_code_config(data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Convertit une config Claude Code (mcpServers) en dictionnaire de serveurs.

    Le format Claude Code regroupe tout sous `mcpServers` avec soit :
      - type 'stdio' : { "command", "args", "env" }
      - type 'http'  : { "url", "headers" }

    On normalise en ajoutant `_type`, `_source` pour que l'auditeur
    puisse traiter chaque entree uniformement.
    """
    servers: Dict[str, Dict[str, Any]] = {}
    mcp_servers = data.get('mcpServers', {})

    for name, cfg in mcp_servers.items():
        server_type = cfg.get('type', 'stdio')  # default est stdio
        entry: Dict[str, Any] = dict(cfg)       # shallow copy
        entry['_type'] = server_type

        if server_type == 'http':
            entry['_source'] = cfg.get('url')
        else:
            # stdio : la source est le binaire command
            entry['_source'] = cfg.get('command')

        servers[name] = entry

    return servers


def find_default_config() -> Optional[Path]:
    """Cherche un fichier de config MCP par defaut.

    Ordre de recherche :
      1. ~/.config/mcp/config.json          (config mcp-audit)
      2. ~/.claude/settings.json             (Claude Code user settings)
      3. ~/.claude.json                      (Claude Code legacy)
      4. ./.mcp.json                         (Claude Code project)
    """
    candidates = [
        Path.home() / '.config' / 'mcp' / 'config.json',
    ] + _claude_code_config_paths()

    for p in candidates:
        if p.exists():
            return p
    return None


class MCPConfig(BaseModel):
    """Modele de configuration MCP."""

    servers: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    tools: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    resources: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    source_format: str = Field(default='native')  # 'native' | 'claude_code' | 'unknown'

    @classmethod
    def load(cls, config_path: Path) -> 'MCPConfig':
        """Charge la configuration depuis un fichier JSON.

        Detecte automatiquement le format (natif ou Claude Code).
        """
        config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(
                f"Fichier de configuration non trouve: {config_path}"
            )

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Erreur JSON dans le fichier de configuration: {e}"
            )
        except Exception as e:
            raise ValueError(
                f"Erreur lors du chargement de la configuration: {e}"
            )

        fmt = detect_config_format(data)

        if fmt == 'claude_code':
            servers = parse_claude_code_config(data)
            return cls(
                servers=servers,
                tools={},
                resources={},
                source_format='claude_code',
            )

        if fmt == 'native':
            return cls(**data, source_format='native')

        # Format inconnu -- on tente quand meme
        return cls(**data, source_format='unknown')

    def get_server_names(self) -> List[str]:
        """Retourne la liste des noms de serveurs MCP."""
        return list(self.servers.keys())

    def get_tool_names(self) -> List[str]:
        """Retourne la liste des noms d'outils MCP."""
        return list(self.tools.keys())

    def get_resource_names(self) -> List[str]:
        """Retourne la liste des noms de ressources MCP."""
        return list(self.resources.keys())

    def get_server_config(self, server_name: str) -> Optional[Dict[str, Any]]:
        """Retourne la configuration d'un serveur specifique."""
        return self.servers.get(server_name)

    def get_tool_config(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Retourne la configuration d'un outil specifique."""
        return self.tools.get(tool_name)

    def get_resource_config(self, resource_name: str) -> Optional[Dict[str, Any]]:
        """Retourne la configuration d'une ressource specifique."""
        return self.resources.get(resource_name)


class MCPDependency(BaseModel):
    """Modele pour une dependance MCP."""

    name: str
    version: Optional[str] = None
    type: str = "tool"  # tool, resource, server
    source: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
