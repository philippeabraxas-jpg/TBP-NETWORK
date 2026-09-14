# Benchmarks de latence — budget de friction (spec §9.1)

Le pilote échoue si ces seuils ne tiennent pas, pas seulement s'il y a un
bug fonctionnel — la friction est une contrainte fondatrice, pas un
détail de perf à optimiser après coup.

| Mesure | Seuil | Source |
|---|---|---|
| Latence ajoutée tier 1 (inoffensif, lecture seule) | < 5 ms | §9.1 |
| Latence tier 1 (cible large) | 2–5 ms | §9 |
| Latence tier 2 (à arbitrer, hors temps humain) | 10–50 ms | §9 |
| Taux d'arbitrage humain | < 10 % des actions | §9.1 |
| Régression d'expérience utilisateur mesurée | = 0 (condition d'échec sinon) | §9.1 |

## Non implémenté ici (placeholder)

- Harnais de charge (k6/locust/autocannon selon la stack finale de
  `src/pep/`) mesurant la latence ajoutée par le PEP seul (hors traducteur,
  hors réseau) pour isoler la variable.
- Suivi dans le temps des **indicateurs annonciateurs** (§9) : taux
  d'arbitrage > 20 %, validations < 5 s, trous non instrumentés, TTL qui
  s'allongent, culture des exceptions — ce sont les signaux de "mort par
  friction" (§9, scénario B) avant qu'il ne soit trop tard pour corriger.
