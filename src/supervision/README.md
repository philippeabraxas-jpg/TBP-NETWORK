# src/supervision — moniteur indépendant (T34, issue #60, §2/§6.2/§7.1)

Le moniteur de supervision est un **processus à clé et log propres** (§2 :
« at least one independent monitor » dans la base de confiance) qui
surveille les chaînes des cellules et la master chain **sans jamais y
écrire**. §7.1 : « cellule à périmètre élargi — mêmes mécaniques, même
doctrine, jamais une nouvelle boîte noire » — son propre log est un
`CellLog` ordinaire (T7), ses feuilles suivent le format hash-only de §6.2.

## Livré (T34a) — moniteurs d'intégrité

| fichier | rôle |
|---|---|
| `alert.go` | record d'alerte canonique « TBPS1 » + couture `AlarmSink` (T14) |
| `watcher.go` | `ChainWatcher` : lecture vérifiée d'un log POSIX Tessera (signature de checkpoint, consistance O(log n), re-hash des feuilles) |
| `monitor.go` | `Monitor` : orchestre les vérificateurs, feuille + alarme chaque divergence |
| `failover.go` | détection de chute (ET strict) + déclenchement borné de bascule (T34b, D80) |
| `console.go` | console HTTP lecture seule PAR CONSTRUCTION (T34c, D81/D82) |

Les trois vérificateurs continus (§6.2, D78) :

1. **Continuité/intégrité des chaînes** — à chaque tick, preuve de
   consistance Merkle du checkpoint N-1 → N (`LogStateTracker`, client
   Tessera) + re-hash RFC 6962 des nouvelles feuilles contre les tuiles.
   Toute discontinuité inexpliquée = corruption = alarme (§3). Une faute
   prouvée est **sticky** : le watcher la rend à chaque tick, sans amnésie
   (§5.3).
2. **Fraîcheur d'ancrage** — lag depuis la dernière feuille `KindAnchor`
   de la cellule dans la master chain (kind + timestamp en clair, payload
   salé opaque : **le sel T6 n'est jamais requis**). Borne par défaut
   120 s (§6.2). « Jamais observé » est une faute comme « trop vieux ».
3. **Cohérence des manifestes** — `VerifyManifestChain` (T31, §6.3) sur
   les artefacts publiés de la cellule, rejouée depuis la genèse à chaque
   passage (artefacts petits et rares ; l'intégrité est la signature).

Chaque divergence = feuille `KindSupervision` (kind 12) dans le log de
supervision, record « TBPS1 » hashé-salé (le sel reste chez le moniteur),
**puis** alarme vers la couture T14 (`AlarmSink`). Jamais l'inverse,
jamais sans la feuille : §5.3 — une alerte non feuillée est une alerte
silencieuse.

## Chemin froid (§9.1)

`CheckOnce` lit des fichiers et vérifie des preuves — il n'est appelé par
aucun composant du chemin chaud (broker/pep n'importent pas ce package,
testé par `TestNoHotPathImport`). Latence ajoutée au tier-1 : **0**. La
cadence de tick est un choix de déploiement (l'appelant boucle).

## Lecture vérifiée d'un log qu'on n'écrit pas

`ChainWatcher` est construit sur le côté lecture du client Tessera v1.0.4
(`FileFetcher` local, `LogStateTracker`, `GetEntryBundle`,
`FetchLeafHashes`) — aucun serveur HTTP requis en P1 (même machine). Le
checkpoint initial est vérifié à la construction (fail-closed) ; un
`bootstrapFrom` permet un audit complet O(n) à l'ouverture (utilisé pour
la master chain et les cellules — borne assumée du pilote P1), puis le
régime permanent est incrémental O(log n).

## Livré (T34b) — détection de chute et bascule bornée (D80)

**Chute** = les DEUX signaux de vie perdus en même temps depuis
`FallDelay` (défaut 240 s) : chaîne figée (taille vérifiée stable) **ET**
aucun ancrage frais. Le ET est porteur : l'ancrage T6 est cadencé par le
temps, pas par l'activité — une cellule vivante mais inactive continue
d'ancrer ; seule une cellule morte perd les deux signaux. L'alarme
`anchor-stale` (borne 120 s) précède toujours la bascule (FallDelay >
MaxAnchorLag imposé à la construction).

**Déclenchement** : couture `FailoverTrigger` vers #30
(`cluster.Tracker`/`PromotionController`) — T34 détecte et déclenche, ne
fence pas (D83). Budget pré-autorisé borné : **2 déclenchements par
fenêtre glissante d'une heure** (défaut, paramétré). NB : ce budget
(moniteur DÉCLENCHE, défaut 2) est distinct de
`MaxAutoFailoversPerHour=3` (src/cluster, T29 — cellule ACCEPTE) ; comme
rien d'autre ne déclenche de bascule auto, le budget du moniteur est de
facto la borne effective, la plus stricte.

Au-delà du budget, couture absente (`Trigger` nil) ou couture en faute :
**escalade humaine** — feuille `KindSupervision` event=5 verdict=Alarm,
aucune bascule automatique supplémentaire. Un déclenchement accepté =
feuille event=4 verdict=Notice (constat d'acte pré-autorisé, feuillé comme
toute alerte). Une chute n'est traitée qu'une fois par épisode ; la
reprise (feuille nouvelle ou ancrage frais) réarme le détecteur.

## Livré (T34c) — console lecture seule (D81/D82)

La console est un serveur HTTP **sans aucune route mutante** : seuls trois
patterns `GET` sont enregistrés — une requête POST/PUT/DELETE reçoit 405
**du mux**, un chemin inconnu 404. Le refus n'est pas un code de garde qui
pourrait être oublié : c'est l'absence matérielle de la route (mutation
M13 prouvée létale — une route mutante ajoutée fait échouer
`TestConsoleReadOnlyByConstruction` immédiatement).

- **`GET /v1/arbitration`** — file d'arbitrage (T30) : `policy_id` (hex,
  claim −1) et plans en attente — **hash scellé**, `submitted_at`,
  `expires_at`, nombre d'étapes. Jamais les étapes ni les paramètres :
  le plan en clair circule sur le canal opérateur, la console n'est pas
  un second canal de lecture (hash-only §6.2). La décision humaine reste
  une signature Ed25519 `Approve` sur ce canal (§4.2) — **la console ne
  peut ni approuver, ni révoquer, ni clore**.
- **`GET /v1/epoch`** — état du suivi d'époque T29 (autorité, bornes,
  quarantaines, bascules auto de l'heure), lisible même en quarantaine.
- **`GET /v1/indicators`** — indicateurs §9.1 :
  `tier1_supervision_latency_added_ns: 0` (mesuré par construction : rien
  de la supervision n'est sur le chemin chaud), taux d'arbitrage
  (`plan_denies/requests` + file en attente), et par cellule taille de
  chaîne vérifiée, fraîcheur d'ancrage (§6.2) et état de chute (T34b).
  Les faits sont bruts, les drapeaux dérivés (`anchor_stale`) marqués
  comme tels.

Lecture **pure** : aucune feuille, aucune alarme, aucune mutation —
l'instantané moniteur est pris sous le même verrou que `CheckOnce`,
jamais à moitié reconstruit. Transport : socket Unix de cellule
(`broker.ListenUnix`, 0660 — l'accès au socket EST le contrôle d'accès,
doctrine v1) ; l'exposition réseau relève de T35. Couture côté T30 :
`ContractStore.Snapshot()`/`PolicyID()`, accesseurs de lecture ajoutés
sans toucher aux feuilles.

## Hors périmètre (rappel #60)

Fencing/quorum/promotion (#30 — appelés, pas réimplémentés), scellement
des plans (T30 — présenté, pas refait), construction des manifestes (T31 —
vérifiée, pas refaite), dashboarding générique, distribution réseau au-delà
du socket Unix local.
