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
from urllib.parse import urlparse, quote
from dateutil import parser

from .config import MCPConfig, MCPDependency

from .scoring import compute_trust_score
from .smithery import (
    is_smithery_source,
    extract_qualified_name,
    fetch_server_info,
    compute_smithery_bonus,
)
from .supply_chain import analyze_transitive_deps


class MCPAudit:
    """Classe principale pour l'audit des dependances MCP."""

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
                'quality_issues': 0,
                'smithery_servers': 0,
                'transitive_deps': 0,
                'transitive_vulns': 0,
            },
            'dependencies': [],
            'vulnerabilities': [],
            'quality_issues': [],
            'recommendations': []
        }

    def audit(self) -> Dict[str, Any]:
        """Execute l'audit complet."""
        if self.verbose:
            print("🔍 Debut de l'audit MCP...")

        # Extraire les dependances
        dependencies = self._extract_dependencies()
        self.results['summary']['total_dependencies'] = len(dependencies)

        # Analyser chaque dependance
        for dep in dependencies:
            self._analyze_dependency(dep)

        # Generer des recommandations
        self._generate_recommendations()

        if self.verbose:
            print(f"✅ Audit termine: {len(dependencies)} dependances analysees")

        return self.results

    def _extract_dependencies(self) -> List[MCPDependency]:
        """Extrait toutes les dependances de la configuration MCP."""
        dependencies = []

        # Format Claude Code : tout est dans servers avec _type/_source
        if self.config.source_format == 'claude_code':
            for server_name, server_config in self.config.servers.items():
                server_type = server_config.get('_type', 'stdio')
                source = server_config.get('_source')

                dep = MCPDependency(
                    name=server_name,
                    type="server",
                    source=source,
                    metadata={
                        'server_type': server_type,
                        **{k: v for k, v in server_config.items()
                           if k not in ('_type', '_source')},
                    },
                )
                dependencies.append(dep)
                if self.verbose:
                    print(f"  📦 Serveur (Claude Code, {server_type}): {server_name}")
        else:
            # Format natif : servers + tools + resources
            for tool_name, tool_config in self.config.tools.items():
                dep = MCPDependency(
                    name=tool_name,
                    type="tool",
                    source=tool_config.get('uri'),
                    metadata=tool_config,
                )
                dependencies.append(dep)
                if self.verbose:
                    print(f"  📦 Outil: {tool_name}")

            for resource_name, resource_config in self.config.resources.items():
                dep = MCPDependency(
                    name=resource_name,
                    type="resource",
                    source=resource_config.get('uri'),
                    metadata=resource_config,
                )
                dependencies.append(dep)
                if self.verbose:
                    print(f"  📦 Ressource: {resource_name}")

            for server_name, server_config in self.config.servers.items():
                command = server_config.get('command', '')
                # Pour npx/uvx, extraire le package depuis args comme source
                resolved_source = command
                args = server_config.get('args', [])
                if command in ('npx', 'uvx') and args:
                    # Trouver le premier arg qui est un nom de package (pas un flag)
                    for arg in args:
                        if not arg.startswith('-'):
                            resolved_source = f"npm:{arg}" if command == 'npx' else f"pypi:{arg}"
                            break

                dep = MCPDependency(
                    name=server_name,
                    type="server",
                    source=resolved_source,
                    metadata=server_config,
                )
                dependencies.append(dep)
                if self.verbose:
                    print(f"  📦 Serveur: {server_name}")

        return dependencies

    def _analyze_dependency(self, dependency: MCPDependency):
        """Analyse une dependance specifique."""
        if self.verbose:
            print(f"  🔍 Analyse de {dependency.name}...")

        # Analyse de qualite
        quality_score = self._assess_quality(dependency)

        # Recherche de vulnerabilites
        vulnerabilities = self._check_vulnerabilities(dependency)

        # Verification de maintenance
        maintenance_status = self._check_maintenance(dependency)

        # Stocker les resultats
        result = {
            'name': dependency.name,
            'type': dependency.type,
            'source': dependency.source,
            'quality_score': quality_score,
            'vulnerabilities': vulnerabilities,
            'maintenance_status': maintenance_status,
            'metadata': dependency.metadata
        }

        # Smithery registry enrichment (before trust score so data is available)
        smithery_info = self._check_smithery(dependency)
        if smithery_info:
            result['smithery'] = smithery_info
            self.results['summary']['smithery_servers'] += 1

        # Transitive dependency analysis (P6) — before trust score so risk_score
        # feeds into the supply-chain pillar (P7)
        transitive = self._analyze_transitive(dependency)
        if transitive:
            result['transitive'] = transitive
            self.results['summary']['transitive_deps'] += transitive.get('total_deps', 0)
            self.results['summary']['transitive_vulns'] += transitive.get('total_vulns', 0)

        # Compute aggregated trust score AFTER all enrichment data is in result
        result['trust_score'] = compute_trust_score(result)

        # Apply Smithery bonus on top of computed trust score
        if smithery_info:
            bonus = compute_smithery_bonus(smithery_info)
            total_bonus = sum(v for v in bonus.values() if isinstance(v, (int, float)))
            result['trust_score']['score'] = min(100, result['trust_score']['score'] + total_bonus)
            result['trust_score']['smithery_bonus'] = total_bonus

        self.results['dependencies'].append(result)

        # Mettre a jour les totaux
        if vulnerabilities:
            self.results['vulnerabilities'].extend(vulnerabilities)
            self.results['summary']['vulnerabilities'] += len(vulnerabilities)

        if quality_score < 70:
            self.results['quality_issues'].append(result)
            self.results['summary']['quality_issues'] += 1

        # Mettre a jour les compteurs par type
        if dependency.type == "tool":
            self.results['summary']['tools'] += 1
        elif dependency.type == "resource":
            self.results['summary']['resources'] += 1
        elif dependency.type == "server":
            self.results['summary']['servers'] += 1

    def _assess_quality(self, dependency: MCPDependency) -> int:
        """Evalue la qualite d'une dependance (0-100)."""
        score = 100
        meta = dependency.metadata

        # Verifier si la source est specifiee
        if not dependency.source:
            score -= 20

        # Pour les serveurs Claude Code, verifier les champs specifiques
        if meta.get('server_type') == 'http':
            # HTTP server : verifier URL
            url = meta.get('url')
            if not url:
                score -= 25
            elif not url.startswith(('http://', 'https://')):
                score -= 15
            # Verifier headers/presence d'auth
            if not meta.get('headers'):
                score -= 10
        elif meta.get('server_type') == 'stdio':
            # STDIO server : verifier command
            cmd = meta.get('command')
            if not cmd:
                score -= 25
            # Verifier args
            if not meta.get('args'):
                score -= 5
        else:
            # Format natif : anciens checks
            if not dependency.metadata.get('version'):
                score -= 10
            if dependency.type == "tool" and dependency.source:
                if not dependency.source.startswith(('http://', 'https://', 'file://')):
                    score -= 15

        return max(0, score)

    def _check_vulnerabilities(self, dependency: MCPDependency) -> List[Dict[str, Any]]:
        """Verifie les vulnerabilites pour une dependance via OSV.dev."""
        vulnerabilities = []

        if not dependency.source:
            return vulnerabilities

        try:
            # Extraire le nom du package de la source
            package_name = self._extract_package_name(dependency.source)
            if not package_name:
                return vulnerabilities

            # Recherche sur OSV.dev
            osv_url = "https://api.osv.dev/v1/query"
            payload = {
                'package': {
                    'name': package_name,
                    'ecosystem': 'npm' if 'npm' in package_name else 'PyPI',
                }
            }

            response = requests.post(osv_url, json=payload, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for vuln in data.get('vulns', []):
                    severity = self._parse_severity(vuln.get('severity', []))
                    if severity:
                        vulnerabilities.append({
                            'id': vuln.get('id', f'UNKNOWN-{len(vulnerabilities)}'),
                            'severity': severity,
                            'description': vuln.get('summary', 'Vulnerabilite inconnue'),
                            'affected_versions': self._extract_affected_versions(vuln),
                            'url': f"https://osv.dev/vuln/{vuln.get('id')}"
                        })

        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Erreur lors de la verification des vulnerabilites pour {dependency.name}: {e}")

        return vulnerabilities

    def _check_maintenance(self, dependency: MCPDependency) -> Dict[str, Any]:
        """Verifie le statut de maintenance d'une dependance."""
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
            # Verifier si c'est un GitHub repository
            github_info = self._analyze_github_source(dependency.source)
            if github_info:
                maintenance_info.update(github_info)

            # Verifier les releases via API npm / PyPI selon la source
            if dependency.source:
                if dependency.source.startswith('npm:') or '.npmjs.com' in dependency.source:
                    pkg_info = self._check_npm_package(dependency)
                    if pkg_info:
                        maintenance_info.update(pkg_info)
                elif dependency.source.startswith('pypi:'):
                    pkg_info = self._check_pypi_package(dependency)
                    if pkg_info:
                        maintenance_info.update(pkg_info)

            # Pour les serveurs avec npx/uvx args, essayer le bon registry
            args = dependency.metadata.get('args', [])
            command = dependency.metadata.get('command', '')
            if args and command in ('npx', 'uvx'):
                for arg in args:
                    if not arg.startswith('-'):
                        if command == 'npx':
                            pkg_info = self._check_npm_package_by_name(arg)
                        else:
                            pkg_info = self._check_pypi_package_by_name(arg)
                        if pkg_info:
                            maintenance_info.update(pkg_info)
                        break

        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Erreur lors de la verification de maintenance pour {dependency.name}: {e}")

        return maintenance_info

    def _extract_package_name(self, source: str) -> Optional[str]:
        """Extrait le nom du package a partir de la source."""
        if source.startswith('npm:'):
            return source[4:]
        elif source.startswith('pypi:'):
            return source[5:]
        elif 'github.com' in source:
            match = re.search(r'github\.com/([^/]+/[^/]+?)(?:\.git)?$', source)
            if match:
                return match.group(1)
        elif source.startswith('http'):
            parsed = urlparse(source)
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) >= 2:
                return f"{path_parts[-2]}/{path_parts[-1]}"

        return None

    def _parse_severity(self, severity_data: List[Dict[str, Any]]) -> Optional[str]:
        """Parse les donnees de severite d'OSV.dev."""
        if not severity_data:
            return None

        severities = []
        for sev in severity_data:
            score = sev.get('score', 0)
            if isinstance(score, str):
                # CVSS vector string — extraire le score
                try:
                    # Format CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
                    pass
                except Exception:
                    pass
                continue
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
        """Extrait les versions affectees a partir d'une vulnerabilite OSV.dev."""
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
        """Analyse une source GitHub pour obtenir des metriques de maintenance."""
        if 'github.com' not in source:
            return None

        try:
            match = re.search(r'github\.com/([^/]+/[^/]+?)(?:\.git)?$', source)
            if not match:
                return None

            repo = match.group(1)
            api_url = f"https://api.github.com/repos/{repo}"

            headers = {}
            github_token = os.environ.get('GITHUB_TOKEN')
            if github_token:
                headers['Authorization'] = f'token {github_token}'

            response = requests.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()

                commit_frequency = 'unknown'
                try:
                    commits_url = f"{api_url}/stats/participation"
                    commits_response = requests.get(commits_url, headers=headers, timeout=5)
                    if commits_response.status_code == 200:
                        participation = commits_response.json()
                        recent_commits = sum(participation.get('all', [])[-4:])
                        if recent_commits > 20:
                            commit_frequency = 'high'
                        elif recent_commits > 5:
                            commit_frequency = 'medium'
                        else:
                            commit_frequency = 'low'
                except Exception:
                    pass

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
        """Obtient la derniere release d'un repo GitHub."""
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
        """Verifie les infos d'un package npm."""
        try:
            package_name = self._extract_package_name(dependency.source)
            if not package_name:
                return None
            return self._check_npm_package_by_name(package_name)
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Erreur lors de la verification npm pour {dependency.name}: {e}")
        return None

    def _check_npm_package_by_name(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Verifie les infos d'un package npm par nom."""
        try:
            # URL-encode le nom du package (requis pour les scoped packages @scope/name)
            encoded_name = quote(package_name, safe='')

            api_url = f"https://registry.npmjs.org/{encoded_name}"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json()

                versions = data.get('time', {})
                last_version = data.get('dist-tags', {}).get('latest')
                last_update = versions.get(last_version, 'unknown')

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
                print(f"  ⚠️  Erreur npm pour {package_name}: {e}")

        return None

    def _check_pypi_package(self, dependency: MCPDependency) -> Optional[Dict[str, Any]]:
        """Verifie les infos d'un package PyPI."""
        try:
            package_name = self._extract_package_name(dependency.source)
            if not package_name:
                return None
            return self._check_pypi_package_by_name(package_name)
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Erreur lors de la verification PyPI pour {dependency.name}: {e}")
        return None

    def _check_pypi_package_by_name(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Verifie les infos d'un package PyPI par nom."""
        try:
            api_url = f"https://pypi.org/pypi/{package_name}/json"
            response = requests.get(api_url, timeout=10)
            if response.status_code == 200:
                data = response.json().get('info', {})
                releases = response.json().get('releases', {})

                latest_version = data.get('version')
                release_entries = releases.get(latest_version, []) if latest_version else []
                last_update = 'unknown'
                if release_entries:
                    last_update = release_entries[-1].get('upload_time_iso_8601', 'unknown')

                releases_count = len([v for v in releases.values() if isinstance(v, list)])
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
                    'latest_version': latest_version,
                    'health': 'good' if latest_version else 'warning'
                }

        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Erreur PyPI pour {package_name}: {e}")

        return None

    def _check_smithery(self, dependency: MCPDependency) -> Optional[Dict[str, Any]]:
        """Check if dependency is a Smithery server and enrich with registry data."""
        if not is_smithery_source(dependency.source, dependency.metadata):
            return None

        qualified_name = extract_qualified_name(dependency.source, dependency.metadata)
        if not qualified_name:
            if self.verbose:
                print(f"  📦 Smithery detected for {dependency.name} but no qualified name found")
            return {"detected": True, "qualified_name": None, "resolved": False}

        if self.verbose:
            print(f"  🔮 Smithery lookup: {qualified_name}")

        server_info = fetch_server_info(qualified_name, verbose=self.verbose)
        if server_info:
            server_info["detected"] = True
            server_info["resolved"] = True
            if self.verbose:
                print(f"  ✅ Smithery: {server_info.get('display_name', qualified_name)} ({server_info.get('tools_count', 0)} tools, scan={'PASS' if server_info.get('security_scan_passed') else 'N/A'})")
        else:
            server_info = {"detected": True, "qualified_name": qualified_name, "resolved": False}
            if self.verbose:
                print(f"  ⚠️  Smithery: {qualified_name} not found in registry")

        return server_info

    def _analyze_transitive(self, dependency: MCPDependency) -> Optional[Dict[str, Any]]:
        """Analyze transitive dependencies for npm/PyPI packages."""
        source = dependency.source
        if not source:
            return None

        package_name = None
        ecosystem = None

        # Determine ecosystem and package name
        if source.startswith('npm:'):
            package_name = source[4:]
            ecosystem = 'npm'
        elif source.startswith('pypi:'):
            package_name = source[5:]
            ecosystem = 'PyPI'
        else:
            # Try to infer from command/args
            command = dependency.metadata.get('command', '')
            args = dependency.metadata.get('args', [])
            if command == 'npx' and args:
                for arg in args:
                    if not arg.startswith('-'):
                        package_name = arg
                        ecosystem = 'npm'
                        break
            elif command == 'uvx' and args:
                for arg in args:
                    if not arg.startswith('-'):
                        package_name = arg
                        ecosystem = 'PyPI'
                        break

        if not package_name or not ecosystem:
            return None

        if self.verbose:
            print(f"  🔗 Transitive analysis: {package_name} ({ecosystem})")

        try:
            return analyze_transitive_deps(
                package_name, ecosystem, verbose=self.verbose
            )
        except Exception as e:
            if self.verbose:
                print(f"  ⚠️  Transitive analysis failed for {package_name}: {e}")
            return None

    def _generate_recommendations(self):
        """Genere des recommandations basees sur l'audit."""
        recommendations = []

        for dep in self.results['dependencies']:
            if dep['vulnerabilities']:
                recommendations.append({
                    'type': 'security',
                    'priority': 'high',
                    'message': f"La dependance '{dep['name']}' a des vulnerabilites connues",
                    'dependency': dep['name']
                })

        for dep in self.results['dependencies']:
            if dep['quality_score'] < 70:
                recommendations.append({
                    'type': 'quality',
                    'priority': 'medium',
                    'message': f"La dependance '{dep['name']}' a un faible score de qualite ({dep['quality_score']}/100)",
                    'dependency': dep['name']
                })

        for dep in self.results['dependencies']:
            if dep['maintenance_status']['health'] == 'warning':
                recommendations.append({
                    'type': 'maintenance',
                    'priority': 'medium',
                    'message': f"La dependance '{dep['name']}' pourrait etre mieux maintenue",
                    'dependency': dep['name']
                })

        self.results['recommendations'] = recommendations
