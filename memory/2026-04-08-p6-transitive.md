# 2026-04-08 - P6 Transitive Dependency Analysis

## Réalisations
- ✅ Module `supply_chain.py` complet (450+ lignes)
- ✅ Résolution BFS arbre de dépendances (npm + PyPI)
- ✅ OSV.dev vulnérabilités par sous-dépendance
- ✅ npm audit / pip-audit CLI integration (auto-detect)
- ✅ Score de risque transitif 0-100
- ✅ Intégration audit.py (_analyze_transitive) + report.py (table)
- ✅ 43 nouveaux tests → 134/134 total
- ✅ PR #7 ouverte + auto-merge squash

## Architecture
- `supply_chain.py` : module standalone, callable depuis audit.py
- Stratégie : CLI tools (npm audit / pip-audit) → fallback registry+OSV
- BFS avec caps : max_depth=3, max 100 packages visités, 20 deps/package
- `compute_transitive_risk_score()` : pénalité basée deps/depth/vulns/severity

## Prochaine action
P7 : Intégrer transitive risk_score dans scoring.py supply_chain pillar
