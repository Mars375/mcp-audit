"""Tests pour le module d'audit"""

import pytest
from mcp_audit.config import MCPConfig
from mcp_audit.audit import MCPAudit


class TestMCPAudit:
    
    def setup_method(self):
        """Préparation des tests."""
        self.config_data = {
            "servers": {
                "test-server": {
                    "command": "python -m server",
                    "args": []
                }
            },
            "tools": {
                "good-tool": {
                    "name": "Good Tool",
                    "uri": "https://example.com/good-tool.py",
                    "version": "1.0.0"
                },
                "bad-tool": {
                    "name": "Bad Tool",
                    "uri": "invalid-uri"
                },
                "no-source-tool": {
                    "name": "No Source Tool"
                }
            },
            "resources": {
                "test-resource": {
                    "uri": "https://example.com/data.json"
                }
            }
        }
        
        self.config = MCPConfig(**self.config_data)
        self.auditor = MCPAudit(self.config, verbose=False)
    
    def test_extract_dependencies(self):
        """Test l'extraction des dépendances."""
        dependencies = self.auditor._extract_dependencies()
        
        assert len(dependencies) == 5  # 1 server + 3 tools + 1 resource
        
        # Vérifier que tous les types sont présents
        types = [dep.type for dep in dependencies]
        assert "server" in types
        assert "tool" in types
        assert "resource" in types
    
    def test_assess_quality(self):
        """Test l'évaluation de la qualité."""
        # Bonne dépendance
        good_dep = type('MockDep', (), {
            'name': 'good-tool',
            'type': 'tool',
            'source': 'https://example.com/good-tool.py',
            'metadata': {'version': '1.0.0'}
        })()
        
        score = self.auditor._assess_quality(good_dep)
        assert score == 100
        
        # Mauvaise dépendance (source invalide)
        bad_dep = type('MockDep', (), {
            'name': 'bad-tool',
            'type': 'tool',
            'source': 'invalid-uri',
            'metadata': {}
        })()
        
        score = self.auditor._assess_quality(bad_dep)
        assert score < 100
    
    def test_check_vulnerabilities(self):
        """Test la vérification des vulnérabilités."""
        # Dépendance sans source = pas de vulnérabilités checkées
        safe_dep = type('MockDep', (), {
            'name': 'safe-tool',
            'source': None
        })()
        vulnerabilities = self.auditor._check_vulnerabilities(safe_dep)
        assert len(vulnerabilities) == 0
        
        # Dépendance avec source mais pas de package connu
        vuln_dep = type('MockDep', (), {
            'name': 'test-tool',
            'source': 'https://example.com/some-package'
        })()
        vulnerabilities = self.auditor._check_vulnerabilities(vuln_dep)
        assert isinstance(vulnerabilities, list)
    
    def test_check_maintenance(self):
        """Test la vérification de maintenance."""
        dep = type('MockDep', (), {
            'name': 'test-tool',
            'source': None
        })()
        maintenance = self.auditor._check_maintenance(dep)
        
        assert 'last_update' in maintenance
        assert 'commit_frequency' in maintenance
        assert 'issues_count' in maintenance
        assert 'health' in maintenance
    
    def test_full_audit(self):
        """Test un audit complet."""
        results = self.auditor.audit()
        
        # Vérifier la structure des résultats
        assert 'summary' in results
        assert 'dependencies' in results
        assert 'vulnerabilities' in results
        assert 'quality_issues' in results
        assert 'recommendations' in results
        
        # Vérifier que les totaux sont cohérents
        summary = results['summary']
        assert summary['total_dependencies'] == len(results['dependencies'])
        assert summary['tools'] == 3
        assert summary['resources'] == 1
        assert summary['servers'] == 1
        
        # Vérifier que les recommandations sont bien une liste
        assert isinstance(results['recommendations'], list)
