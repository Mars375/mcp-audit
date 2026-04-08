# 2026-04-08 16:36 - Chantier mcp-audit - Cron P3

## Statut
- **Phase**: ACTIVE
- **Repo**: https://github.com/Mars375/mcp-audit
- **43/43 tests passent**

## Actions réalisées
- ✅ P3 implémenté : `--fail-under <score>` CLI option
- ✅ Exit code 1 si un serveur a un trust score < seuil
- ✅ Message d'erreur clair listant les serveurs défaillants (nom, score, grade)
- ✅ Fonctionne en mode `--ci` et interactif
- ✅ 9 nouveaux tests (pass/fail/boundary/mixed/unit)
- ✅ PR #4 merged (squash)
- ✅ PRIORITIES.md mis à jour (P3 → DONE)
- ✅ ACTIVE.md mis à jour

## Prochaine action
P4 — GitHub Action prête à l'emploi (.github/actions/mcp-audit/action.yml)
