#!/usr/bin/env python3
"""
Test d'intégration API pour mcp-audit
"""

import sys
import json
from pathlib import Path

# Ajouter le répertoire courant au path
sys.path.insert(0, str(Path(__file__).parent))

def test_api_integration():
    """Test l'intégration des APIs externes"""
    print("🧪 Test d'intégration API...")
    
    try:
        from mcp_audit.config import MCPConfig
        from mcp_audit.audit import MCPAudit
        
        # Charger la configuration test
        config_path = Path(__file__).parent / "sample_config.json"
        config = MCPConfig.load(config_path)
        
        # Créer un auditor
        auditor = MCPAudit(config, verbose=True)
        
        # Exécuter l'audit
        print("🔍 Exécution de l'audit avec API réelles...")
        results = auditor.audit()
        
        # Vérifier que les résultats contiennent les données attendues
        assert 'summary' in results
        assert 'dependencies' in results
        assert len(results['dependencies']) > 0
        
        # Vérifier que les API externes ont été appelées
        for dep in results['dependencies']:
            if dep['source'] and 'github.com' in dep['source']:
                assert 'maintenance_status' in dep
                assert 'health' in dep['maintenance_status']
                print(f"✅ GitHub API analysé: {dep['name']} ({dep['maintenance_status']['health']})")
            
            if dep['source'] and dep['source'].startswith('npm:'):
                assert 'maintenance_status' in dep
                print(f"✅ npm API analysé: {dep['name']}")
        
        print("✅ Test d'intégration API: OK")
        return True
        
    except Exception as e:
        print(f"❌ Test d'intégration API: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_sample_config():
    """Test le chargement de la configuration sample"""
    print("🧪 Test de configuration...")
    
    try:
        from mcp_audit.config import MCPConfig
        
        config_path = Path(__file__).parent / "sample_config.json"
        config = MCPConfig.load(config_path)
        
        # Vérifier que la configuration est valide
        assert len(config.get_tool_names()) == 3
        assert len(config.get_resource_names()) == 2
        assert len(config.get_server_names()) == 2
        
        print("✅ Configuration: OK")
        return True
        
    except Exception as e:
        print(f"❌ Configuration: {e}")
        return False

def main():
    """Run API integration tests"""
    print("🚀 Démarrage des tests d'intégration API...")
    
    tests = [
        test_sample_config,
        test_api_integration
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"📊 Résultats: {passed}/{total} tests passés")
    
    if passed == total:
        print("🎉 Tous les tests d'intégration passés !")
        return True
    else:
        print("❌ Certains tests ont échoué")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)