# PRIORITIES.md — Feuille de route du chantier mcp-audit

> Ce fichier est le pilote du cron forge-chantier-mcp-audit.
> Le cron lit ce fichier au début de chaque session et travaille sur la première priorité OPEN.
> Si toutes les priorités sont DONE → le cron travaille sur les issues GitHub ouvertes.
> forge-maintainer peut modifier ce fichier pour orienter le chantier.

## Format
- `[ ]` OPEN — à faire
- `[~]` IN PROGRESS — commencé, continuer
- `[x]` DONE — terminé

---

## [x] P1 — Support config Claude Code MCP (~/.claude/settings.json)
**Objectif** : Lire et auditer les serveurs MCP configurés dans Claude Code.

**Résultat** : Implémenté 2026-04-08. Auto-détection format (native vs mcpServers), support stdio + HTTP, auto-find chemins. 19 tests, 33 total.

Validation : `mcp-audit scan --config ~/.claude/settings.json` produit un rapport.

---

## [x] P2 — Score de confiance agrégé par serveur MCP
**Objectif** : Score composite (qualité + sécurité + maintenance + supply chain) affiché en une ligne par serveur.

**Résultat** : Implémenté 2026-04-08. Support npm scoped + PyPI, score /100 par serveur, couleurs Rich, 34 tests verts.

Validation : rapport terminal avec score /100 par serveur, couleur rouge/jaune/vert.

---

## [x] P3 — Mode CI (exit code non-zéro si score < seuil)
**Objectif** : Utilisable dans un pipeline GitHub Actions pour bloquer un merge si un serveur MCP est risqué.

**Résultat** : Implémenté 2026-04-08. Option --fail-under <score>, exit 1 si serveur < seuil, message clair, 9 tests.

Validation : `mcp-audit scan --fail-under 70` retourne exit code 1 si un serveur < 70.

---

## [x] P4 — GitHub Action prête à l'emploi
**Objectif** : Action composite réutilisable pour les workflows GitHub Actions.

**Résultat** : Implémenté 2026-04-08. `.github/actions/mcp-audit/action.yml` avec 6 inputs (config, fail-under, output, github-token, python-version, verbose). Workflow d'exemple `.github/workflows/audit-example.yml`. README mis à jour avec documentation complète.

Validation : Action composite valide, inputs documentés, artifact upload automatique.

---

## [x] P5 — Support Smithery registry
**Objectif** : Détecter et auditer les serveurs MCP installés via Smithery.

**Résultat** : Implémenté 2026-04-08. Module smithery.py complet : détection auto (CLI args, source prefix, metadata marker), résolution qualified name, requête registry public + API authentifiée, enrichissement audit (security scan, tools count, transport), bonus scoring (max +10). 34 tests unitaires + integration.

Validation : serveurs avec `smithery:ns/server` ou `@smithery/cli` dans args → enrichis avec données Smithery registry.

---

## [x] P6 — Score de risque supply-chain avancé
**Objectif** : Analyse transitive des dépendances npm/PyPI des serveurs MCP.

**Résultat** : Implémenté 2026-04-08. Module `supply_chain.py` complet : résolution BFS arbre de dépendances (npm registry + PyPI API), vérification OSV.dev par sous-dépendance, support CLI `npm audit` / `pip-audit` si disponibles, score de risque transitif 0-100. Intégré dans audit.py + report.py (section transitive). 43 tests unitaires.

Validation : serveurs npm/PyPI → arbre de dépendances résolu avec vulnérabilités transitives dans le rapport.

---

## [x] P7 — Score de risque supply-chain dans le trust score composite
**Objectif** : Intégrer le `transitive.risk_score` de P6 dans le pillar supply-chain de `scoring.py`.

Ajuster `_supply_chain_pillar()` pour pénaliser les serveurs dont le risque transitif est élevé (risk_score > 50 → -10, > 75 → -20). Afficher le détail dans le JSON report.

---

## [x] P8 — SBOM export (CycloneDX / SPDX)
**Objectif** : Exporter la liste complète des dépendances transitives au format CycloneDX JSON ou SPDX.

Ajouter option CLI `--sbom cyclonedx|spdx`. Utilise les données de `supply_chain.py` pour générer un SBOM standardisé. Intégration CI possible avec dependency-track ou grype.

---

## [x] P9 — Cache intelligent des requêtes registry
**Objectif** : Mettre en cache les réponses npm/PyPI/OSV.dev pour accélérer les audits répétés.

**Résultat** : Implémenté 2026-04-09. Module cache.py complet : cache JSON fichier avec TTL configurable (24h defaut), clé déterministe GET/POST (hash SHA256 du body), stats hit/miss, cleanup expired, singleton global. Intégré dans audit.py, supply_chain.py, smithery.py. CLI --no-cache et --cache-ttl. 38 tests unitaires, conftest.py pour isolation.

Validation : `mcp-audit scan --verbose` affiche stats cache. Deuxième run = hits sur toutes les requêtes registry.


---

## [x] P10 — Config .mcp-audit.yaml pour options par défaut
**Objectif** : Fichier de config utilisateur pour les options par défaut du CLI (cache TTL, fail-under, output format, etc.).

**Résultat** : Implémenté 2026-04-09. Support de `~/.config/mcp-audit/config.yaml` et `./.mcp-audit.yaml`, merge user < project < CLI, validation des clés/valeurs, génération de config sample, 32 tests dédiés.

Validation : `python main.py --config sample_config.json` applique les defaults définis dans les fichiers YAML sans écraser les flags CLI explicites.

---

## [x] P11 — Format de rapport Markdown
**Objectif** : Ajouter un format de rapport Markdown en plus de terminal + JSON.

**Résultat** : Implémenté 2026-04-09. Option `--format markdown`, export fichier `.md`, génération Markdown avec sections résumé / trust score / dépendances transitives / vulnérabilités / recommandations. Support config utilisateur `format: markdown`. README mis à jour. 8 nouveaux tests dédiés, 276 tests verts.

Validation : `python main.py --format markdown --output audit-report.md` génère un rapport Markdown lisible.

---

## [x] P12 — Watch mode (audit continu)
**Objectif** : Mode surveillance qui re-audite automatiquement quand la config MCP change.

**Résultat** : Implémenté 2026-04-09. Option CLI `--watch`, boucle de surveillance légère sans dépendance externe, ré-audit automatique au changement de fichier, fonctionnement non interactif en watch mode, 3 tests dédiés, 279 tests verts.

Validation : `python main.py --config .mcp.json --watch` relance un audit dès que le fichier surveillé change.
