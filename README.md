# mcp-audit

CLI Python pour auditer les dépendances MCP — qualité, sécurité, maintenance, risques supply chain.

## 🚀 Fonctionnalités

- ✅ **Configuration MCP** : Parsing avec validation Pydantic
- ✅ **Audit qualité** : Évaluation 0-100 basée sur métriques réelles
- ✅ **Sécurité** : Détection de vulnérabilités via OSV.dev
- ✅ **Maintenance** : Statut GitHub, fréquence des commits, releases
- ✅ **Rapports** : Terminal coloré (Rich) + export JSON
- ✅ **Mode CI** : Rapport léger pour intégration continue
- ✅ **API externes** : GitHub, OSV.dev, npm registry

## 📦 Installation

```bash
# Cloner le repo
git clone <repo-url>
cd mcp-audit

# Installer les dépendances
pip install -r requirements.txt
```

## 🎯 Usage

### Basic usage
```bash
# Audit interactif avec affichage détaillé
python main.py --config sample_config.json --verbose

# Mode CI (rapport JSON seulement pour CI/CD)
python main.py --ci --output audit-report.json

# Spécifier un fichier de configuration personnalisé
python main.py --config /path/to/your/mcp-config.json
```

### Configuration requise pour les APIs

#### GitHub API
```bash
# Optionnel: Définir un token GitHub pour plus de limites
export GITHUB_TOKEN=ghp_your_token_here
```

#### Variables d'environnement
```bash
# Token GitHub (optionnel mais recommandé)
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx

# Pour les audits en production
export MCP_AUDIT_MODE=production
```

## 📊 Exemples de rapports

### Rapport terminal
```bash
$ python main.py --config sample_config.json --verbose
🔍 Début de l'audit MCP...
  📦 Outil: file-browser
  🔍 Analyse de file-browser...
  📦 Ressource: current-directory
  🔍 Analyse de current-directory...
  📦 Serveur: filesystem
  🔍 Analyse de filesystem...
✅ Audit terminé: 7 dépendances analysées

📊 Résumé:
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Total        ┃ 7              ┃
┃ Vulnérabilités┃ 0              ┃
┃ Qualité      ┃ 85/100         ┃
┃ Recommandations┃ 2              ┃
┗━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━┛
```

### Rapport JSON
```json
{
  "summary": {
    "total_dependencies": 7,
    "tools": 3,
    "resources": 2,
    "servers": 2,
    "vulnerabilities": 0,
    "quality_issues": 1,
    "average_quality": 78
  },
  "dependencies": [
    {
      "name": "file-browser",
      "type": "tool",
      "quality_score": 95,
      "vulnerabilities": [],
      "maintenance_status": {
        "health": "good",
        "last_update": "2024-03-15",
        "stars": 42
      }
    }
  ],
  "recommendations": [
    {
      "type": "quality",
      "priority": "medium",
      "message": "La dépendance 'test-tool' a un faible score de qualité (45/100)"
    }
  ]
}
```

## 🔧 Use Case - Audit de sécurité MCP

### Scénario
Auditer une configuration MCP critique pour un projet de production :

1. **Configuration MCP**
```json
{
  "servers": {
    "production-db": {
      "command": "node server.js",
      "env": { "NODE_ENV": "production" }
    }
  },
  "tools": {
    "payment-processor": {
      "uri": "https://github.com/company/payment-processor"
    },
    "auth-service": {
      "uri": "npm:@company/auth-service@2.1.0"
    }
  }
}
```

2. **Exécution de l'audit**
```bash
python main.py --config production-mcp.json --ci --output security-audit.json
```

3. **Analyse des résultats**
- Vérification des vulnérabilités CVE connues
- Statut de maintenance des dépendances
- Score qualité global
- Recommandations prioritaires

## 📁 Structure du projet
```
mcp-audit/
├── main.py                    # CLI entry point
├── requirements.txt           # Dépendances
├── sample_config.json         # Configuration type
├── audit-report.json          # Rapport généré
├── mcp_audit/
│   ├── __init__.py
│   ├── config.py              # Parsing configuration
│   ├── audit.py               # Logique d'audit
│   └── report.py              # Génération rapports
└── tests/
    ├── test_config.py
    └── test_audit.py
```

## ✅ Critères de qualité

L'outil respecte les bonnes pratiques :
- ✅ Gestion d'erreurs réseau robuste
- ✅ Analyse asynchrone pour les APIs externes
- ✅ Validation de configuration Pydantic
- ✅ Rapports détaillés et exploitables
- ✅ Mode CI/CD intégré
- ✅ Gestion des tokens et sécurité

## 🚀 Développement

### Tests
```bash
# Exécuter tous les tests
python run_tests.py

# Exécuter un test spécifique
python -m unittest tests.test_config
```

### Contribuer

1. Fork le repository
2. Créer une branche pour votre feature
3. Faire des tests et commit
4. Ouvrir un PR avec description détaillée

## 📈 Performance

- **Temps d'audit** : < 30s pour 50 dépendances
- **API Rate Limits** : Respect des limites publiques (GitHub: 60/h, OSV.dev: 1000/jour)
- **Mémoire** : < 50MB pour 100+ dépendances
- **Fiabilité** : Gestion des erreurs réseau et timeouts

## 🔄 Évolution future

- [ ] Support de registres privés
- [ ] Dashboard web intégré
- [ ] Intégration avec Slack/Teams
- [ ] Historique d'audit
- [ ] Alertes automatisées

## 📄 Licence

MIT License - voir fichier LICENSE

## 🔗 Liens utiles

- [MCP Specification](https://modelprotocol.io/)
- [OSV.dev](https://osv.dev/)
- [GitHub API](https://docs.github.com/en/rest)
- [Rich CLI](https://github.com/Textualize/rich)