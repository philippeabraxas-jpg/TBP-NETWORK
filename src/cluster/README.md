# Fencing du cluster (T29)

Fencing multi-cellule du réseau TBP (spec §7.2–§7.5, issue
[#30](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/30)) :
**époques à autorité unique**, **quorum k-of-n pour la classe W**,
**promotion miroir/canari par preuve de réception**. §7.2/§13 : ce package
est requis avant **tout** déploiement multi-cellule, pilote P1 à 2
cellules compris — « a single cell can defer this, a pilot cannot ».

Doctrine (§7.1) : une cellule est du bétail, jamais une racine de
confiance. Ce package ne **détient aucune clé privée** : les jetons
d'époque sont signés m-of-n par les contrôleurs (HSM, cérémonie hors-bande
— la genèse epoch 0 vient de `scripts/genesis`, T3) ; ici on **vérifie**
et on applique mécaniquement. Fail-closed partout (§1), chaque décision
laisse une feuille (§4.1), hash-only (§6.2 : le sel ≥ 16 octets reste chez
le producteur), Ed25519 partout (§12), sérialisation canonique
déterministe (§11.3).

## Fichiers

- **`epoch.go`** — `Tracker` : la machine à états d'époques d'UNE cellule.
  Vérifie les jetons m-of-n (jamais le champ `quorum` déclaratif), impose
  N strictement monotone, détecte l'équivoque (deux jetons valides au même
  N ⇒ refus + alarme), borne le TTL [10 s, 300 s] (§7.2 ~60 s), borne les
  bascules automatiques (`MaxAutoFailoversPerHour`, défaut 3 — « max N
  bascules/heure, ensuite humain » : au-delà, seul un epoch `mode=manual`
  du canal séparé pré-autorisé passe), applique les révocations à roster
  réduit (§7.3). Implémente `broker.EpochProvider` — `CurrentEpoch()
  (uint64, error)` : **pas d'époque valide dont cette cellule est
  l'autorité ⇒ erreur ⇒ la cellule ne sert pas**.
- **`quorum.go`** — `QuorumGate` : co-signature k-of-n de la classe W
  (§7.5 : « a single cell, adversarial or captured, cannot authorize the
  maximal irreversible »). Vérification **purement locale** (aucun réseau,
  hors chemin chaud §9.1) : le demandeur collecte les co-signatures des
  contrôleurs AVANT de se présenter ; la preuve lie `(action, resource,
  policy_id, epoch, expiry)`. Implémente `broker.QuorumGate` — le câblage
  broker est fail-closed : classe W sans quorum satisfait ⇒ refus.
- **`promotion.go`** — `PromotionController` : promotion miroir/canari
  (§7.4). Les entrées sont **uniquement** les ancres du master (hash du
  bundle par époque, fenêtre saine définie+ancrée) via la couture
  `MasterAnchorSource` ; la promotion exige la **preuve de réception** du
  bundle ancré, signée par la clé Ed25519 de la cellule candidate. L'API
  n'accepte **aucune donnée de santé du candidat** — la fenêtre n'est
  jamais mesurée par le canari lui-même ; sous partition, l'ancre est
  illisible et toute promotion est refusée (un canari ne peut pas
  s'auto-promouvoir).

## Règle d'autorité unique (§7.2)

« Seul le détenteur sert, l'ancien expire tout seul. » Concrètement :

- N **strictement monotone** : un jeton N ≤ courant est refusé
  (`epoch-regression`) ; deux jetons valides au même N avec des payloads
  différents = faute byzantine (`epoch-equivocation`, alarme).
- Si le nouveau jeton arrive **avant** l'expiration de l'ancien, la
  nouvelle autorité n'entre en fonction qu'à `expiresAt` de l'ancienne
  (`notBefore`) — **jamais de fenêtre de double autorité**, au prix d'un
  trou de service borné (fail-closed : personne ne sert plutôt que deux).
- Une cellule qui apprend l'époque N+1 cesse **immédiatement** de servir,
  même si son propre jeton n'est pas expiré.
- Expiration sans successeur ⇒ aucune autorité ⇒ la cellule refuse de
  servir (`ErrEpochExpired`) — le broker traduit en `epoch-unavailable`
  (refus + feuille + alarme, avant toute traduction).

## Révocation = nouvelle époque à roster réduit (§7.3)

Le champ optionnel `roster` du payload signé liste les cellules
survivantes. Les membres absents du roster passent en **quarantaine** —
pas en suppression : l'état de la cellule gelée reste **inspectable**
(`Status()`, `Quarantined()`), rien n'est purgé. La mise en quarantaine
est une décision **du quorum** (le roster est partie intégrante du payload
signé), jamais du tracker. Les jetons pré-émis par la cellule révoquée —
et par toute autre — sont invalidés par l'incrément d'époque : le PEP les
refuse en `epoch-mismatch` (claim −6, couture T8/T9 éprouvée par le test
croisé de `cluster_test.go`).

## Format du jeton d'époque — continuité T3

Layout **identique** à `scripts/genesis` (T3) : payload JSON canonique
`(n, authority, issued_at, ttl_s)` + signatures `{key_id, sig}` indexées
sur le manifest des contrôleurs distribué hors-bande à la genèse (§3.2 :
la légitimité reste hors protocole). Deux champs `omitempty` ajoutés —
l'epoch 0 de la genèse, qui ne les porte pas, s'importe **tel quel**
(verrouillé par `TestGenesisEpochZeroImport`, qui frappe le JSON à la
main dans le layout exact de `genesis.go`) :

| champ    | rôle                                                                  |
|----------|-----------------------------------------------------------------------|
| `mode`   | `"auto"` (failover pré-autorisé, compté dans le budget) \| `"manual"` (cérémonie / canal séparé) — **absent ⇒ `"manual"`** |
| `roster` | cellules survivantes — **présent ⇒ révocation** (§7.3)                |

## Feuilles (§4.1, §6.2)

Trois kinds ajoutés à `registry` (le kind est en clair dans l'en-tête de
feuille — la supervision T34 filtre sans sel ; un kind par catégorie,
convention T4–T23) :

| kind | event/verdict | record (avant hash salé) |
|------|---------------|--------------------------|
| `KindEpoch=7` | 1=accept, 2=refuse, 3=équivoque, 4=révocation, 5=budget épuisé | `"TBPE1" ‖ event ‖ n u64 ‖ authority ‖ reason` |
| `KindQuorum=8` | verdict 0/1 | `"TBPQ1" ‖ verdict ‖ valid ‖ k ‖ epoch u64 ‖ action ‖ reason` |
| `KindPromotion=9` | verdict 0/1 | `"TBPP1" ‖ verdict ‖ cellID ‖ epoch u64 ‖ bundleHash 32B ‖ reason` |

Un **refus non traçable** (feuille impossible) est rendu comme erreur
distincte ; une **admission** (bascule, quorum, promotion) dont la feuille
ne peut être écrite **re-bascule en refus** — pas de preuve, pas d'accès
(même doctrine que T9/T33). Les tests prouvent les feuilles par re-hash
avec le sel révélé.

## Coutures

- `LeafSink` — registre de cellule (T7) ; `*registry.CellLog` l'implémente.
- `MasterAnchorSource` — lecture des ancres du master (bundle par époque,
  fenêtre saine) ; l'implémentation réelle lit la master chain (T6) et est
  branchée en T31 (manifeste attesté, #32) / T34 (supervision, #60).
- `CellKeys` (`PromotionConfig`) — clés publiques Ed25519 des cellules
  candidates, pour la vérification des réceptions.
- `Now` — horloge NTS de la cellule (§6.2) ; injectée dans les tests.
- `OnAlarm` — vers T14 : équivoque, budget de bascule épuisé.

## Ce que ce package ne fait PAS

- **La cérémonie de genèse** — T3 (`scripts/genesis`) : quorum humain, HSM
  véritables, canal hors-bande. Ici : la rotation à partir de l'époque 0.
- **La signature des jetons d'époque / preuves de quorum** — les clés des
  contrôleurs vivent dans des HSM (§12) ; ce package **vérifie**, il ne
  signe jamais.
- **La distribution des jetons** — le canal de bascule (séparé,
  pré-autorisé pour le manuel) est un transport ; ici la machine à états
  qui tranche ce qui est accepté.
- **La master chain** — T6 fournit l'ancrage, T31/T34 branchent la lecture.
- **§7.6/§7.7** — explicitement hors périmètre de l'issue #30.

## Tests

`cluster_test.go`, `quorum_test.go`, `promotion_test.go` — horloges
injectées (déterminisme), critères d'acceptation de #30 tous exercés :

- failover à 2 cellules **sans fenêtre de double autorité** (balayage à la
  seconde) ; vieux jeton re-présenté refusé ; expiration sans successeur =
  pas de service ;
- révocation d'une cellule compromise via roster réduit ; quarantaine
  **inspectable** ; jetons pré-émis refusés post-bascule (test croisé avec
  le validateur T9 : `epoch-mismatch`) ;
- classe W sans quorum refusée, avec k-of-n admise et tracée (y compris le
  câblage broker : `src/broker/quorum_epoch_test.go`) ;
- canari incapable de s'auto-promouvoir sous partition simulée ; seule la
  preuve de réception du bundle ancré promeut ;
- chaque bascule/révocation/décision de quorum/promotion laisse sa feuille,
  prouvée par re-hash avec le sel révélé ;
- non-vacuole : mutations M1–M5 (quorum d'époque neutralisé, `notBefore`
  supprimé, liaison de quorum neutralisée, partition ignorée, câblage
  broker retiré) — chacune fait échouer les tests, revert vérifié vert.
