"""
Gestion de la configuration MCP
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, validator


class MCPConfig(BaseModel):
    """Modèle de configuration MCP."""
    
    servers: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    tools: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    resources: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    
    @classmethod
    def load(cls, config_path: Path) -> 'MCPConfig':
        """Charge la configuration depuis un fichier JSON."""
        config_path = Path(config_path)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Fichier de configuration non trouvé: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return cls(**data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Erreur JSON dans le fichier de configuration: {e}")
        except Exception as e:
            raise ValueError(f"Erreur lors du chargement de la configuration: {e}")
    
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
        """Retourne la configuration d'un serveur spécifique."""
        return self.servers.get(server_name)
    
    def get_tool_config(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Retourne la configuration d'un outil spécifique."""
        return self.tools.get(tool_name)
    
    def get_resource_config(self, resource_name: str) -> Optional[Dict[str, Any]]:
        """Retourne la configuration d'une ressource spécifique."""
        return self.resources.get(resource_name)


class MCPDependency(BaseModel):
    """Modèle pour une dépendance MCP."""
    
    name: str
    version: Optional[str] = None
    type: str = "tool"  # tool, resource, server
    source: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)