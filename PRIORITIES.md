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

## [ ] P6 — Score de risque supply-chain avancé
**Objectif** : Analyse transitive des dépendances npm/PyPI des serveurs MCP.

Étendre l'audit au-delà du package direct : vérifier les sous-dépendances pour vulnérabilités et risques. Utiliser `pip audit` et `npm audit` quand disponibles.
