"""
Core MCP Audit functionality
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
import requests

from .config import MCPConfig, MCPDependency


class MCPAudit:
    """Cl principale pour l'audit des dépendances MCP."""
    
    def __init__(self, config: MCPConfig, verbose: bool = False):
        self.config = config
        self.verbose = verbose
        self.results: Dict[str, Any] = {
            'summary': {
                'total_dependencies': 0,
                'tools': 0,
                'resources': 0,
                'servers': 0,
                'vulnerabilities': 0,
                'quality_issues': 0
            },
            'dependencies': [],
            'vulnerabilities': [],
            'quality_issues': [],
            'recommendations': []
        }
    
    def audit(self) -> Dict[str, Any]:
        """Exécute l'audit complet."""
        if self.verbose:
            print("🔍 Début de l'audit MCP...")
        
        # Extraire les dépendances
        dependencies = self._extract_dependencies()
        self.results['total_dependencies'] = len(dependencies)
        
        # Analyser chaque dépendance
        for dep in dependencies:
            self._analyze_dependency(dep)
        
        # Générer des recommandations
        self._generate_recommendations()
        
        if self.verbose:
            print(f"✅ Audit terminé: {len(dependencies)} dépendances analysées")
        
        return self.results
    
    def _extract_dependencies(self) -> List[MCPDependency]:
        """Extrait toutes les dépendances de la configuration MCP."""
        dependencies = []
        
        # Extraire les outils
        for tool_name, tool_config in self.config.tools.items():
            dep = MCPDependency(
                name=tool_name,
                type="tool",
                source=tool_config.get('uri'),
                metadata=tool_config
            )
            dependencies.append(dep)
            if self.verbose:
                print(f"  📦 Outil: {tool_name}")
        
        # Extraire les ressources
        for resource_name, resource_config in self.config.resources.items():
            dep = MCPDependency(
                name=resource_name,
                type="resource",
                source=resource_config.get('uri'),
                metadata=resource_config
            )
            dependencies.append(dep)
            if self.verbose:
                print(f"  📦 Ressource: {resource_name}")
        
        # Extraire les serveurs
        for server_name, server_config in self.config.servers.items():
            dep = MCPDependency(
                name=server_name,
                type="server",
                source=server_config.get('command'),
                metadata=server_config
            )
            dependencies.append(dep)
            if self.verbose:
                print(f"  📦 Serveur: {server_name}")
        
        return dependencies
    
    def _analyze_dependency(self, dependency: MCPDependency):
        """Analyse une dépendance spécifique."""
        if self.verbose:
            print(f"  🔍 Analyse de {dependency.name}...")
        
        # Analyse de qualité
        quality_score = self._assess_quality(dependency)
        
        # Recherche de vulnérabilités
        vulnerabilities = self._check_vulnerabilities(dependency)
        
        # Vérification de maintenance
        maintenance_status = self._check_maintenance(dependency)
        
        # Stocker les résultats
        result = {
            'name': dependency.name,
            'type': dependency.type,
            'source': dependency.source,
            'quality_score': quality_score,
            'vulnerabilities': vulnerabilities,
            'maintenance_status': maintenance_status,
            'metadata': dependency.metadata
        }
        
        self.results['dependencies'].append(result)
        
        # Mettre à jour les totaux
        if vulnerabilities:
            self.results['vulnerabilities'].extend(vulnerabilities)
            self.results['summary']['vulnerabilities'] += len(vulnerabilities)
        
        if quality_score < 70:
            self.results['quality_issues'].append(result)
            self.results['summary']['quality_issues'] += 1
        
        # Mettre à jour les compteurs par type
        if dependency.type == "tool":
            self.results['summary']['tools'] += 1
        elif dependency.type == "resource":
            self.results['summary']['resources'] += 1
        elif dependency.type == "server":
            self.results['summary']['servers'] += 1
    
    def _assess_quality(self, dependency: MCPDependency) -> int:
        """Évalue la qualité d'une dépendance (0-100)."""
        score = 100
        
        # Vérifier si la source est spécifiée
        if not dependency.source:
            score -= 20
        
        # Vérifier si la version est spécifiée
        if not dependency.metadata.get('version'):
            score -= 10
        
        # Vérifier si l'URI est valide pour les outils
        if dependency.type == "tool" and dependency.source:
            if not dependency.source.startswith(('http://', 'https://', 'file://')):
                score -= 15
        
        return max(0, score)
    
    def _check_vulnerabilities(self, dependency: MCPDependency) -> List[Dict[str, Any]]:
        """Vérifie les vulnérabilités pour une dépendance."""
        vulnerabilities = []
        
        # TODO: Implémenter la vérification réelle via OSV.dev
        # Pour l'instant, une simulation
        
        if dependency.name.lower() in ['test-tool', 'vulnerable-tool']:
            vulnerabilities.append({
                'id': 'CVE-2026-TEST-001',
                'severity': 'high',
                'description': 'Vulnérabilité de test',
                'affected_versions': ['< 1.0.0']
            })
        
        return vulnerabilities
    
    def _check_maintenance(self, dependency: MCPDependency) -> Dict[str, Any]:
        """Vérifie le statut de maintenance d'une dépendance."""
        # TODO: Implémenter la vérification réelle via GitHub API
        # Pour l'instant, une simulation
        
        return {
            'last_update': '2024-01-01',
            'commit_frequency': 'low',
            'issues_count': 5,
            'health': 'warning'
        }
    
    def _generate_recommendations(self):
        """Génère des recommandations basées sur l'audit."""
        recommendations = []
        
        # Vérifier les dépendances avec vulnérabilités
        for dep in self.results['dependencies']:
            if dep['vulnerabilities']:
                recommendations.append({
                    'type': 'security',
                    'priority': 'high',
                    'message': f"La dépendance '{dep['name']}' a des vulnérabilités connues",
                    'dependency': dep['name']
                })
        
        # Vérifier les dépendances de mauvaise qualité
        for dep in self.results['dependencies']:
            if dep['quality_score'] < 70:
                recommendations.append({
                    'type': 'quality',
                    'priority': 'medium',
                    'message': f"La dépendance '{dep['name']}' a un faible score de qualité ({dep['quality_score']}/100)",
                    'dependency': dep['name']
                })
        
        # Vérifier les dépendances mal maintenues
        for dep in self.results['dependencies']:
            if dep['maintenance_status']['health'] == 'warning':
                recommendations.append({
                    'type': 'maintenance',
                    'priority': 'medium',
                    'message': f"La dépendance '{dep['name']}' pourrait être mieux maintenue",
                    'dependency': dep['name']
                })
        
        self.results['recommendations'] = recommendations