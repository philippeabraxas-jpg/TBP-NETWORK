# Harnais de friction — budget §9.1 (T27, issue #29)

Le pilote échoue si les seuils de latence ne tiennent pas, pas seulement
s'il y a un bug fonctionnel — la friction est une contrainte fondatrice,
pas un détail de perf à optimiser après coup.

## ⚠ Production : ce que paie réellement chaque décision aujourd'hui

Le chemin déployé (pepd + registre tessera POSIX) écrit la feuille de
décision **synchrone, fail-closed, avant le verdict** (T9 : « pas de
preuve, pas d'accès »). `CellLog.Append` attend l'intégration ET la
publication du checkpoint ; le driver POSIX impose `CheckpointInterval ≥
100 ms` (borne dure) et l'awaiter polle à 50 ms. Mesuré : **~150–250 ms
par décision, sur CHAQUE évaluation** — 30–50× le budget §9.1. Ce n'est ni
un artefact de mesure ni un mauvais réglage de batch : c'est structurel au
backend d'écriture actuel. **Suivi dédié : issue #71** (sync/async du
registre = chantier d'architecture, hors scope T27). Ce chiffre est
toujours rapporté côte à côte avec le bras « décision » — jamais masqué.

## Deux bras de mesure (D88 amendé, arbitrage revue #29)

| Bras | Puits de feuilles | Mesure | Verdict |
|---|---|---|---|
| **décision** | in-memory synchrone | coût de décision du PEP seul (Ed25519, CBOR, anti-rejeu T10, quota T12, gate T14) — le « plancher déterministe » du §9.1 | **bloquant CI** |
| **durabilité** | registre tessera réel (POSIX) | coût de la preuve fail-closed (feuille intégrée/publiée avant verdict) + feuilles réelles pour la corrélation | surveillé (alerte si p95 > 3× CheckpointInterval), **hors §9.1, suivi #71** |

La synchronicité et la doctrine T9 sont intactes dans les deux bras : même
chemin de code, même `ReasonLeafWriteFailed` — seule la vitesse du magasin
de feuilles change. C'est une technique de mesure, pas un changement
d'architecture.

## Topologie (D85) — le PEP seul, isolé

Pile réelle assemblée avec les mêmes constructeurs que pepd (T15), **OPA
nil** (pas de sidecar), handlers invoqués via `httptest.NewRecorder` —
**aucun socket, aucun réseau, aucun traducteur**. Tier2 = contrat de plan
T30 piloté en appels Go directs sur `pep.ContractStore`
(`Submit`/`Approve`/`VerifyStep`) — jamais par le broker (qui ajouterait
traducteur + quorum + enveloppe à la latence mesurée). Baseline = handler
no-op invoqué à l'identique ; latence ajoutée = pXX(PEP) − pXX(baseline).
Passe de chauffe jetée (§9.1 budgète le régime établi).

## Seuils

| Mesure | Seuil | Source | Verdict |
|---|---|---|---|
| Latence ajoutée tier 1 (décision − baseline) | p95 < 5 ms | §9.1 | **bloquant** |
| Tier2 verify (bras décision) | p95 ≤ 50 ms | §9 (borne haute) | **bloquant** |
| Taux d'arbitrage (refus VerifyStep) | alerte ≥ 10 %, danger ≥ 20 % | §9/§9.1 | **bloquant** |
| Trous non instrumentés (feuilles sans échantillon) | = 0 | D88 | **bloquant** |
| validation p99 (bras décision) | ≤ 5 ms soutenu | §9 | avertissement |
| Durabilité tier1 p95 | ≤ 3× CheckpointInterval | #71 | avertissement |
| TTL émis (p50) | ≤ 2× TTL nominal | §9 (ttl_drift) | avertissement |

La borne basse du §9 pour tier2 (10 ms) est une enveloppe incluant
l'attente opérateur hors champ de mesure — une mesure sous-enveloppe est
informationnelle, jamais un échec de friction (les budgets de friction sont
des maxima).

## Indicateurs avancés (D89) — feuilles réelles, alarmés, leafés

`leading_indicators.py` calcule sur `leaves_export.json` (scan vérifié du
registre réel par le `ChainWatcher` de supervision — pas de deuxième
lecteur tessera) corrélé à `measurements.json` :

- `arbitration_rate` — refus VerifyStep / vérifications (vérité comptée
  par le harnais) ;
- `validation_p99` — p99 des validations tier1 (bras décision) ;
- `uninstrumented_holes` — |feuilles KindDecision/KindContract réelles −
  attendues| ; compté, jamais ignoré ;
- `ttl_drift` — distribution des TTL **émis** (vérité de menthe) : la
  dérive vers le haut = pression de friction (on émet plus long pour
  éviter l'arbitrage).

Chaque franchissement est alarmé dans `friction_report.json`, puis le
rapport est inscrit comme feuille `KindTelemetry` du registre du run
(D90 — hash salé, sel ≥ 16 octets conservé local, jamais commité) et la
feuille est revérifiée au scan.

## Usage

```sh
go run ./tests/p1_friction run         # mesure + measurements.json + leaves_export.json
python3 tests/p1_friction/leading_indicators.py --in out   # verdict (exit 1 = CI rouge)
go run ./tests/p1_friction leaf-report # rapport leafé KindTelemetry (D90)
```

Flags de mutation (garde-fous prouvés létaux par harness_test.go) :
`-inject-latency` (M-harness), `-inject-deny-rate` (M-arbitrage),
`-ttl-stretch` (M-ttl) ; M-holes = tronquer leaves_export.json.

## CI (D91)

`friction_thresholds.yml` est **prêt à copier** vers
`.github/workflows/` (les écritures workflows ne sont pas poussables par
l'agent — 403). Chaîne : tests du harnais (-race) → unittest python →
mesure → verdict bloquant → alarme leafée → artefact.

## k6 (D86 — forme opérationnelle, non bloquante)

`latency_pep.js` / `baseline.js` : mesure contre un pepd vivant (pilotes,
topologie lab T19) — la soustraction p95(pep) − p95(baseline) donne la
latence ajoutée du **chemin complet** (registre inclus : rouge tant que
#71 est ouvert — voir l'avertissement en tête de latency_pep.js). Le
moteur de mesure CI reste le runner Go : déterministe, in-process, sans
installation k6. Jeton via `TBP_TOKEN_B64` (réutilisation ⇒ anti-rejeu T10
à partir de la 2ᵉ requête — journalisé en mode monitor §5.3, chemin
complet tout de même exercé).

## Hors scope

Traducteur (aucun serveur Go côté translator), réseau/loopback, sidecar
OPA, modification des agrégats TBAG1 (T22), nouveau kind de feuille,
console (T34c), modèle sync/async du registre (#71).
