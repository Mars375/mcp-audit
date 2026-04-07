#!/usr/bin/env python3
"""
Test rapide de l'outil mcp-audit
"""

import sys
import os
from pathlib import Path

# Ajouter le répertoire courant au path
sys.path.insert(0, str(Path(__file__).parent))

from mcp_audit.config import MCPConfig
from mcp_audit.audit import MCPAudit
from mcp_audit.report import ReportGenerator


def test_basic_audit():
    """Test de base de l'audit avec la configuration sample."""
    print("🧪 Test de base de l'audit MCP...")
    
    # Charger la configuration sample
    config_path = Path(__file__).parent / "sample_config.json"
    config = MCPConfig.load(config_path)
    
    # Créer l'auditeur
    auditor = MCPAudit(config, verbose=True)
    
    # Exécuter l'audit
    results = auditor.audit()
    
    # Vérifier les résultats
    assert 'summary' in results
    assert 'dependencies' in results
    assert len(results['dependencies']) > 0
    
    print(f"✅ Audit réussi: {len(results['dependencies'])} dépendances analysées")
    
    # Générer un rapport terminal
    generator = ReportGenerator(results, verbose=True)
    terminal_report = generator.generate_terminal_report()
    
    # Sauvegarder le rapport
    output_path = Path(__file__).parent / "test_report.txt"
    with open(output_path, 'w') as f:
        f.write(terminal_report)
    
    print(f"📄 Rapport généré: {output_path}")
    
    return True


if __name__ == "__main__":
    try:
        test_basic_audit()
        print("🎉 Tous les tests passés !")
    except Exception as e:
        print(f"❌ Test échoué: {e}")
        sys.exit(1)