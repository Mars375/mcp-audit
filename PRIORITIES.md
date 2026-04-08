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

## [ ] P2 — Score de confiance agrégé par serveur MCP
**Objectif** : Score composite (qualité + sécurité + maintenance + supply chain) affiché en une ligne par serveur.

Validation : rapport terminal avec score /100 par serveur, couleur rouge/jaune/vert.

---

## [ ] P3 — Mode CI (exit code non-zéro si score < seuil)
**Objectif** : Utilisable dans un pipeline GitHub Actions pour bloquer un merge si un serveur MCP est risqué.

Validation : `mcp-audit scan --fail-under 70` retourne exit code 1 si un serveur < 70.

---

## [ ] P4 — GitHub Action prête à l'emploi
**Objectif** : Action réutilisable publiée sur GitHub Marketplace.

Fichier `.github/actions/mcp-audit/action.yml` avec inputs configurables.
