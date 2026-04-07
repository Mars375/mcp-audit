# mcp-audit

CLI Python pour auditer les dépendances MCP — qualité, sécurité, maintenance, risques supply chain.

## Fonctionnalités

- Lit la configuration MCP
- Interroge mcp-quality-index
- Récupère informations depuis GitHub API
- Vérifie les vulnerabilities via OSV.dev
- Produit un rapport terminal + JSON
- Mode CI optionnel

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Audit interactif
python main.py

# Mode CI (rapport JSON seulement)
python main.py --ci --output audit-report.json

# Spécifier un fichier de config MCP
python main.py --config /path/to/mcp-config.json
```

## Dépendances

- `requests` : HTTP requests
- `click` : CLI interface
- `pydantic` : validation des données
- `rich` : affichage terminal

## Développement

```bash
python -m pytest tests/
```

## TODO

- [x] Structure de projet
- [ ] Parsing de configuration MCP
- [ ] Connexion mcp-quality-index
- [ ] Integration GitHub API
- [ ] Integration OSV.dev
- [ ] Generation rapport
- [ ] Mode CI
- [ ] Tests unitaires
- [ ] Documentation complète
- [ ] Use case documenté