"""
Core MCP Audit functionality
"""

import asyncio
import json
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
import requests
import re
import time
from urllib.parse import urlparse
from dateutil import parser

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
        """Vérifie les vulnérabilités pour une dépendance via OSV.dev."""
        vulnerabilities = []
        
        if not dependency.source:
            return vulnerabilities
        
        try:
            # Extraire le nom du package de la source
            package_name = self._extract_package_name(dependency.source)
            if not package_name:
                return vulnerabilities
            
            # Recherche sur OSV.dev
            osv_url = f"https://api.osv.dev/v1/vulns"
            params = {'package': {'name': package_name}}
            
            response = requests.get(osv_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulns', []):
                    severity = self._parse_severity(vuln.get('severity', []))
                    if severity:
                        vulnerabilities.append({
                            'id': vuln.get('id', f'UNKNOWN-{len(vulnerabilities)}'),
                            'severity': severity,
                            'description': vuln.get('summary', 'Vulnérabilité inconnue'),
                            'affected_versions': self._extract_affected_versions(vuln),
                            'url': f"https://osv.dev/vuln/{vuln.get('id')}"
                        })
            
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Erreur lors de la vérification des vulnérabilités pour {dependency.name}: {e}")
        
        return vulnerabilities
    
    def _check_maintenance(self, dependency: MCPDependency) -> Dict[str, Any]:
        """Vérifie le statut de maintenance d'une dépendance."""
        maintenance_info = {
            'last_update': 'unknown',
            'commit_frequency': 'unknown',
            'issues_count': 0,
            'health': 'unknown',
            'stars': 0,
            'last_release': None
        }
        
        if not dependency.source:
            return maintenance_info
        
        try:
            # Vérifier si c'est un GitHub repository
            github_info = self._analyze_github_source(dependency.source)
            if github_info:
                maintenance_info.update(github_info)
            
            # Vérifier les releases via API npm pour les packages npm
            if dependency.source.startswith('npm:') or '.npmjs.com' in dependency.source:
                npm_info = self._check_npm_package(dependency)
                if npm_info:
                    maintenance_info.update(npm_info)
            
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Erreur lors de la vérification de maintenance pour {dependency.name}: {e}")
        
        return maintenance_info
    
    def _extract_package_name(self, source: str) -> Optional[str]:
        """Extrait le nom du package à partir de la source."""
        if source.startswith('npm:'):
            return source[4:]  # Enlève 'npm:'
        elif 'github.com' in source:
            # Extraire le nom du repo GitHub
            match = re.search(r'github\.com/([^/]+/[^/]+?)(?:\.git)?$', source)
            if match:
                return match.group(1)
        elif source.startswith('http'):
            # Essayer d'extraire à partir de l'URL
            parsed = urlparse(source)
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) >= 2:
                return f"{path_parts[-2]}/{path_parts[-1]}"
        
        return None
    
    def _parse_severity(self, severity_data: List[Dict[str, Any]]) -> Optional[str]:
        """Parse les données de sévérité d'OSV.dev."""
        if not severity_data:
            return None
        
        # Trouver la sévérité la plus élevée
        severities = []
        for sev in severity_data:
            score = sev.get('score', 0)
            if score >= 9.0:
                severities.append('critical')
            elif score >= 7.0:
                severities.append('high')
            elif score >= 4.0:
                severities.append('medium')
            else:
                severities.append('low')
        
        return severities[0] if severities else None
    
    def _extract_affected_versions(self, vuln: Dict[str, Any]) -> List[str]:
        """Extrait les versions affectées à partir d'une vulnérabilité OSV.dev."""
        affected_versions = []
        
        for affected in vuln.get('affected', []):
            for range_info in affected.get('ranges', []):
                for event in range_info.get('events', []):
                    if event.get('introduced'):
                        affected_versions.append(f">= {event['introduced']}")
                    if event.get('fixed'):
                        affected_versions.append(f"< {event['fixed']}")
        
        return affected_versions if affected_versions else ['Toutes les versions']
    
    def _analyze_github_source(self, source: str) -> Optional[Dict[str, Any]]:
        """Analyse une source GitHub pour obtenir des métriques de maintenance."""
        if 'github.com' not in source:
            return None
        
        try:
            # Extraire le nom du repo
            match = re.search(r'github\.com/([^/]+/[^/]+?)(?:\.git)?$', source)
            if not match:
                return None
            
            repo = match.group(1)
            api_url = f"https://api.github.com/repos/{repo}"
            
            # Ajouter token si disponible
            headers = {}
            github_token = os.environ.get('GITHUB_TOKEN')
            if github_token:
                headers['Authorization'] = f'token {github_token}'
            
            response = requests.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Calculer la fréquence des commits
                commit_frequency = 'unknown'
                try:
                    commits_url = f"{api_url}/stats/participation"
                    commits_response = requests.get(commits_url, headers=headers, timeout=5)
                    if commits_response.status_code == 200:
                        participation = commits_response.json()
                        recent_commits = sum(participation.get('all', [])[-4:])  # Derniers 4 mois
                        if recent_commits > 20:
                            commit_frequency = 'high'
                        elif recent_commits > 5:
                            commit_frequency = 'medium'
                        else:
                            commit_frequency = 'low'
                except Exception:
                    # Si on ne peut pas récupérer les stats de participation, on ignore
                    pass
                
                # Déterminer la santé
                health = 'good'
                if data.get('archived', False):
                    health = 'archived'
                elif data.get('disabled', False):
                    health = 'disabled'
                elif data.get('stargazers_count', 0) < 10:
                    health = 'warning'
                
                return {
                    'last_update': data.get('updated_at', 'unknown'),
                    'commit_frequency': commit_frequency,
                    'stars': data.get('stargazers_count', 0),
                    'forks': data.get('forks_count', 0),
                    'issues_count': data.get('open_issues_count', 0),
                    'health': health,
                    'last_release': self._get_latest_release(repo, headers)
                }
        
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Erreur lors de l'analyse GitHub {source}: {e}")
        
        return None
    
    def _get_latest_release(self, repo: str, headers: Dict[str, str]) -> Optional[str]:
        """Obtient la dernière release d'un repo GitHub."""
        try:
            api_url = f"https://api.github.com/repos/{repo}/releases/latest"
            response = requests.get(api_url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('published_at', 'unknown')
        except Exception:
            pass
        return None
    
    def _check_npm_package(self, dependency: MCPDependency) -> Optional[Dict[str, Any]]:
        """Vérifie les infos d'un package npm."""
        try:
            package_name = self._extract_package_name(dependency.source)
            if not package_name:
                return None
            
            api_url = f"https://registry.npmjs.org/{package_name}"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                
                # Vérifier la dernière version
                versions = data.get('time', {})
                last_version = data.get('dist-tags', {}).get('latest')
                last_update = versions.get(last_version, 'unknown')
                
                # Calculer la santé basée sur la fréquence des releases
                releases_count = len([v for v in versions.values() if isinstance(v, str)])
                release_frequency = 'unknown'
                if releases_count > 50:
                    release_frequency = 'high'
                elif releases_count > 10:
                    release_frequency = 'medium'
                else:
                    release_frequency = 'low'
                
                return {
                    'last_update': last_update,
                    'commit_frequency': release_frequency,
                    'latest_version': last_version,
                    'health': 'good' if last_version else 'warning'
                }
        
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Erreur lors de la vérification npm pour {dependency.name}: {e}")
        
        return None
    
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