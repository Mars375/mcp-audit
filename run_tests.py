#!/usr/bin/env python3
"""
Simple test runner for mcp-audit
"""

import sys
import os
from pathlib import Path

# Ajouter le répertoire courant au path
sys.path.insert(0, str(Path(__file__).parent))

def test_config():
    """Test the config module"""
    print("🧪 Test du module de configuration...")
    
    try:
        from mcp_audit.config import MCPConfig, MCPDependency
        
        # Test loading sample config
        config_path = Path(__file__).parent / "sample_config.json"
        config = MCPConfig.load(config_path)
        
        assert len(config.get_tool_names()) == 3
        assert len(config.get_resource_names()) == 2
        assert len(config.get_server_names()) == 2
        
        print("✅ Module de configuration: OK")
        return True
        
    except Exception as e:
        print(f"❌ Module de configuration: {e}")
        return False

def test_audit():
    """Test the audit module"""
    print("🧪 Test du module d'audit...")
    
    try:
        from mcp_audit.config import MCPConfig
        from mcp_audit.audit import MCPAudit
        
        # Load sample config
        config_path = Path(__file__).parent / "sample_config.json"
        config = MCPConfig.load(config_path)
        
        # Run audit
        auditor = MCPAudit(config, verbose=False)
        results = auditor.audit()
        
        assert 'summary' in results
        assert 'dependencies' in results
        assert len(results['dependencies']) == 7  # 3 tools + 2 resources + 2 servers
        
        print("✅ Module d'audit: OK")
        return True
        
    except Exception as e:
        print(f"❌ Module d'audit: {e}")
        return False

def test_report():
    """Test the report module"""
    print("🧪 Test du module de rapport...")
    
    try:
        from mcp_audit.config import MCPConfig
        from mcp_audit.audit import MCPAudit
        from mcp_audit.report import ReportGenerator
        
        # Load sample config and run audit
        config_path = Path(__file__).parent / "sample_config.json"
        config = MCPConfig.load(config_path)
        auditor = MCPAudit(config, verbose=False)
        results = auditor.audit()
        
        # Generate reports
        generator = ReportGenerator(results, verbose=False)
        terminal_report = generator.generate_terminal_report()
        json_report = generator.generate_json_report()
        
        assert len(terminal_report) > 0
        assert 'metadata' in json_report
        assert 'summary' in json_report
        
        print("✅ Module de rapport: OK")
        return True
        
    except Exception as e:
        print(f"❌ Module de rapport: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Démarrage des tests pour mcp-audit...")
    
    tests = [
        test_config,
        test_audit,
        test_report
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print(f"📊 Résultats: {passed}/{total} tests passés")
    
    if passed == total:
        print("🎉 Tous les tests passés !")
        return True
    else:
        print("❌ Certains tests ont échoué")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)