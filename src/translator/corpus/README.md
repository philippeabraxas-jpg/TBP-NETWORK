# corpus/ — structure des corpus natifs du traducteur (T26, §4.5)

Mesure qualité du traducteur (issue #22) : corpus **natifs par langue**,
positifs et négatifs, rejoués à chaque mise à jour du modèle par
`../measure.py` (bloquant en CI), complétés par l'échantillonnage humain
stratifié (`../sample_human.py`).

## Arborescence

```
corpus/<lang>/<classe>/pos/*.txt   — cas que le traducteur DOIT accepter (traduire)
corpus/<lang>/<classe>/neg/*.txt   — cas qu'il DOIT refuser
```

- `<lang>` : code langue natif du cas (`fr`, `en`, `ar`, …) — un corpus
  par langue RÉELLE d'usage, jamais traduit d'une autre (natif, §4.5).
- `<classe>` ∈ `F`, `I`, `W`, `OUT` (hors-classe) — classes de ressource §5.3.
- Un fichier par cas, texte brut UTF-8, nom stable (le chemin relatif est
  l'identifiant du cas dans le replay).
- `example/` : mini-corpus d'EXEMPLE livré avec le pipeline — il valide la
  chaîne (hash, métriques, gate), il n'est PAS un corpus natif.

## Hash du corpus

`measure.py` calcule un hash déterministe du corpus entier (sha256 sur les
couples triés « chemin relatif, sha256 du fichier ») : toute mutation de
contenu ou d'arborescence change le hash. Le hash part dans le rapport et
dans la feuille de métriques (« TBTM1 ») — le lien métriques ↔ corpus exact
est opposable (§6.2).

## Gate CI

`measure.py` sort en code **1** si une classe dépasse les cibles
(FNR < 0,1 %, FPR < 2 %) — à brancher comme étape bloquante à chaque mise
à jour du traducteur. **Ces cibles sont des cibles de conception à valider
sur le premier corpus natif au pilote (§15)** — le rapport les affiche
comme telles, jamais comme des résultats établis. Le dépôt ne peut pas
modifier ses workflows depuis l'agent (403) : l'étape à copier est
documentée dans `src/translator/README.md`.

## Chaîne complète

```
measure.py  --corpus-dir corpus/ --scorer-cmd <scorer T24> --out report.json
tmetrics    --report report.json          # feuille « TBTM1 » hash-only (§6.2)
sample_human.py --in decisions.jsonl --rate 0.01 --seed <consignée> \
    --out echantillon.jsonl --manifest manifeste.json
```

Les corpus natifs eux-mêmes restent **à constituer au pilote** (livrable
associé de l'issue) — cette structure est le contenant vérifié, pas le
contenu.
