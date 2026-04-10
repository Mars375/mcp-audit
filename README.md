# mcp-audit

CLI Python pour auditer les dépendances MCP — qualité, sécurité, maintenance, risques supply chain.

Lit votre config MCP, interroge OSV.dev + GitHub API + npm registry, produit un rapport terminal + JSON + Markdown.
Mode CI optionnel. Supporte les formats **natif**, **Claude Code** (`~/.claude/settings.json`), et **`.mcp.json`**.

## 🚀 Fonctionnalités

- ✅ **Multi-format** : Natif mcp-audit, Claude Code (`mcpServers`), `.mcp.json`
- ✅ **Auto-détection** : Trouve automatiquement votre config MCP
- ✅ **Audit qualité** : Évaluation 0-100 basée sur métriques réelles
- ✅ **Sécurité** : Détection de vulnérabilités via OSV.dev
- ✅ **Maintenance** : Statut GitHub, fréquence des commits, releases
- ✅ **Rapports** : Terminal coloré (Rich) + export JSON + Markdown
- ✅ **Mode CI** : Rapport léger + `--fail-under` pour bloquer les merges
- ✅ **API externes** : GitHub, OSV.dev, npm registry
- ✅ **GitHub Action** : Action composite réutilisable pour vos workflows
- ✅ **Config utilisateur** : `~/.config/mcp-audit/config.yaml` et `.mcp-audit.yaml`
- ✅ **Watch mode** : `--watch` relance automatiquement l'audit quand la config change

## 📦 Installation

```bash
# Cloner le repo
git clone https://github.com/Mars375/mcp-audit.git
cd mcp-audit

# Installer les dépendances
pip install -r requirements.txt
```

## 🎯 Usage

### Basic usage
```bash
# Audit interactif — auto-detecte le fichier de config
python main.py --verbose

# Specifier un fichier explicitement
python main.py --config sample_config.json --verbose

# Auditer une config Claude Code
python main.py --config ~/.claude/settings.json --verbose

# Auditer un .mcp.json projet
python main.py --config .mcp.json

# Mode CI (rapport JSON seulement)
python main.py --ci --output audit-report.json

# Générer un rapport Markdown lisible pour une PR ou un README
python main.py --format markdown --output audit-report.md

# Surveiller une config MCP pendant le développement
python main.py --config .mcp.json --watch

# CI gate: échoue si un serveur a un score < 70
python main.py --ci --fail-under 70
```

### GitHub Action — Usage dans vos workflows

Utilisez l'action composite directement dans vos workflows CI :

```yaml
jobs:
  mcp-security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6

      - name: MCP Audit
        uses: Mars375/mcp-audit/.github/actions/mcp-audit@master
        with:
          config: '.mcp.json'
          fail-under: '70'
          output: mcp-audit-report.json
          github-token: ${{ secrets.GITHUB_TOKEN }}
          verbose: 'true'
```

#### Inputs de l'action

| Input | Description | Défaut |
|-------|-------------|--------|
| `config` | Chemin vers la config MCP (auto-détecté si vide) | `""` |
| `fail-under` | Score minimum /100 pour réussir | `""` |
| `output` | Chemin du rapport JSON/Markdown | `mcp-audit-report.json` |
| `github-token` | Token GitHub pour les appels API | `${{ github.token }}` |
| `python-version` | Version Python | `3.12` |
| `verbose` | Sortie verbeuse | `false` |

L'action upload automatiquement le rapport en artifact (`mcp-audit-report`), même en cas d'échec.

### Auto-détection des chemins

Si `--config` n'est pas spécifié, mcp-audit cherche dans l'ordre :

1. `~/.config/mcp/config.json` (config mcp-audit)
2. `~/.claude/settings.json` (Claude Code)
3. `~/.claude.json` (Claude Code legacy)
4. `./.mcp.json` (projet courant)

### Formats de configuration supportés

#### Format natif mcp-audit
```json
{
  "servers": { "filesystem": { "command": "python -m mcp.server.filesystem" } },
  "tools": { "browser": { "uri": "https://github.com/org/mcp-browser" } },
  "resources": { "home": { "uri": "file:///home" } }
}
```

#### Format Claude Code / `.mcp.json`
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
      "env": {}
    },
    "context7": {
      "type": "http",
      "url": "https://mcp.context7.com/mcp",
      "headers": { "API_KEY": "${CONTEXT7_API_KEY}" }
    }
  }
}
```

### Configuration requise pour les APIs

```bash
# Optionnel: Token GitHub pour plus de limites
export GITHUB_TOKEN=ghp_your_token_here
```

## 🔧 Use Case — Audit Claude Code

### Scénario
Auditer tous les serveurs MCP configurés dans votre Claude Code :

```bash
$ python main.py --config ~/.claude/settings.json --verbose
🔍 Début de l'audit MCP...
Configuration chargée depuis: /home/user/.claude/settings.json
Format détecté: claude_code
Serveurs: 3
  📦 Serveur (Claude Code, stdio): filesystem
  📦 Serveur (Claude Code, http): context7
  📦 Serveur (Claude Code, stdio): github
✅ Audit terminé: 3 dépendances analysées
```

## 🔧 Use Case — Audit CI/CD

```bash
# Pipeline GitHub Actions
python main.py --ci --fail-under 70 --output security-audit.json
```

## 🔧 Use Case — Watch mode

```bash
# Relance automatiquement l'audit quand .mcp.json change
python main.py --config .mcp.json --watch
```

Le watch mode surveille le fichier de configuration MCP cible et relance immédiatement un audit à chaque modification. Pratique pendant le développement d'un serveur MCP ou d'une config Claude Code.

## 📁 Structure du projet
```
mcp-audit/
├── main.py                              # CLI entry point
├── requirements.txt                     # Dépendances
├── sample_config.json                   # Config type (natif)
├── sample_claude_code_config.json       # Config type (Claude Code)
├── .github/
│   ├── actions/mcp-audit/
│   │   └── action.yml                   # Action composite réutilisable
│   └── workflows/
│       └── audit-example.yml            # Workflow d'exemple
├── mcp_audit/
│   ├── __init__.py
│   ├── config.py                        # Parsing config (multi-format)
│   ├── audit.py                         # Logique d'audit
│   ├── scoring.py                       # Scores de confiance /100
│   └── report.py                        # Génération rapports
└── tests/
    ├── test_config.py                   # Tests config natif
    ├── test_audit.py                    # Tests audit
    ├── test_claude_code_config.py       # Tests format Claude Code
    ├── test_scoring.py                  # Tests scoring
    └── test_ci_fail_under.py           # Tests mode CI
```

## ✅ Tests

```bash
# Exécuter tous les tests
python -m pytest -v

# Tests du support Claude Code uniquement
python -m pytest tests/test_claude_code_config.py -v
```

## 📈 Performance

- **Temps d'audit** : < 30s pour 50 dépendances
- **API Rate Limits** : Respect des limites publiques
- **Mémoire** : < 50MB pour 100+ dépendances

## Smithery Registry Support

mcp-audit automatically detects and enriches MCP servers installed via [Smithery](https://smithery.ai):

**Detection methods:**
- `smithery:` prefix in source (e.g., `smithery:owner/server`)
- `@smithery/cli` in command or args
- `_registry: smithery` metadata marker

**Enrichment data from Smithery registry:**
- Security scan status (pass/fail)
- Tool count and resource count
- Transport type (stdio / http)
- Display name and description

**Scoring bonus (up to +10 points):**

| Factor | Bonus |
|--------|-------|
| Security scan passed | +5 |
| High tool count (>=10) | +3 |
| Medium tool count (>=3) | +1 |
| Tools + resources both present | +2 |

**Environment variable:**
- `SMITHERY_API_KEY` - Optional. Enables authenticated API access for private servers.

**Example config:**
```json
{
  "servers": {
    "my-smithery-srv": {
      "command": "npx",
      "args": ["-y", "@smithery/cli", "run", "@owner/server"]
    }
  }
}
```

## 🔄 Évolution future

- [ ] Support de registres privés
- [ ] Dashboard web intégré
- [x] Support Smithery registry (auto-detect + scoring)
- [ ] Score de risque supply-chain avancé

## 📄 Licence

MIT License - voir fichier LICENSE

## 🔗 Liens utiles

- [MCP Specification](https://modelprotocol.io/)
- [OSV.dev](https://osv.dev/)
- [Claude Code MCP](https://docs.anthropic.com/en/docs/claude-code/mcp)
- [GitHub Actions](https://docs.github.com/en/actions)
- [Rich CLI](https://github.com/Textualize/rich)
