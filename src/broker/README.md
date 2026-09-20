# Broker de cellule (T33 + câblage T29)

Le broker est le **point d'entrée unique** du flux de décision d'une
cellule TBP (spec §5.1 : « no direct client → server path ; the server
accepts only the broker »). Il orchestre la chaîne complète, de la demande
de l'agent au jeton/passeport signé — ou au refus tracé.

## Périmètre

Ce package construit (issue [#59](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/59), câblage fencing/quorum de [#30](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/30)) :

- **L'orchestration** (`broker.go`) — pour chaque demande, dans l'ordre
  strict, sans raccourci : bornes d'entrée → tirage du `jti` → **époque**
  (§7.2, T29 : `CurrentEpoch() (uint64, error)` — une erreur refuse
  `epoch-unavailable` AVANT la traduction, avec feuille et alarme ; une
  implémentation ne peut jamais servir une époque périmée en silence) →
  traduction (couture) → évaluation OPA (client T11, réutilisé tel quel) →
  **quorum classe W** (§7.5, T29 : toute demande classée W — claim −4=W
  **ou absent**, défaut §5.3 — sans quorum satisfait est refusée
  `quorum-required`/`quorum-insufficient`, même patron
  optionnel-mais-fail-closed qu'`Envelope`/`Ledger`) → enveloppe
  d'émission §4.1-bis si passeport → signature → feuilles. Fail-closed à
  chaque étape : la moindre faute bascule en refus avec feuille, **jamais
  d'émission partielle**.
- **L'émetteur de jetons** (`issuer.go`) — CWT + COSE_Sign1 + CBOR
  déterministe, strictement selon `src/pep/token/schema.md` (T8) : claims
  fermées, TTL borné [30, 60] s (§4.1), `kid = SHA-256(clé publique)[0:16]`
  résolu dans le trousseau épinglé côté PEP. La signature est une couture
  (`Signer`) : HSM en production (§12) ; `DevSigner` est **dev/test
  uniquement**, même restriction que SoftHSM.
- **L'enveloppe d'émission** (`envelope.go`, §4.1-bis) — quota agrégé par
  entité et par époque. Séparation stricte des responsabilités (§1) : le
  `EnvelopeLedger` **compte** (état borné §4.3, saturation = refus +
  alarme latchée, jamais d'éviction), OPA **décide** (règle d'enveloppe
  du bundle signé — aucun seuil n'est codé en dur ici). Réservation
  pessimiste : le volume est réservé avant l'appel OPA, les demandes en
  vol comptent — une course concurrente peut sur-refuser, jamais
  sur-émettre.
- **Le serveur HTTP** (`server.go`) — `POST /v1/actions`, JSON borné
  64 Kio, stdlib uniquement. Un refus est une décision valide
  (`200 {"allow": false, …}`), pas une erreur de transport.

## Ce que ce package ne fait PAS (explicitement hors périmètre, #59)

- **Le traducteur lui-même** — T24–T26 construisent son runtime durci ;
  ici la couture `Translator`. `StructuredTranslator` est le mode
  structuré sans modèle (brique de la dégradation contrôlée T25).
- **La validation de jeton côté ressource** — T8–T17 (`src/pep/`). Le test
  croisé `broker_test.go` fait valider chaque jeton émis par le
  validateur T9 : un seul format, vérifié des deux côtés.
- **Le fencing d'époque et le quorum eux-mêmes** — T29 (#30,
  `src/cluster/`) livre `cluster.Tracker` (implémente `EpochProvider`) et
  `cluster.QuorumGate` (implémente `QuorumGate`) ; ici les coutures et leur
  câblage fail-closed. `StaticEpoch` reste marqué **dev mono-cellule** ;
  en déploiement multi-cellule l'époque vient du fencing (§7.2 : seule la
  détentrice sert). La preuve de quorum transite en blob opaque
  (`quorum_proof`, hex, borné 4096 o) dans l'intention structurée — relayée
  telle quelle au gate, jamais interprétée ici (no-DPI).
- **L'escalade vers l'arbitrage humain** (§4.5 degraded modes, tier « à
  arbitrer ») — couture ultérieure (T25/T30) : aujourd'hui un « je ne sais
  pas traduire » ou un deny OPA est un refus, point.
- **L'authentification réseau des agents** — v1 : socket Unix de cellule,
  pas de TLS ni d'auth applicative. L'admission réseau relève du NAC
  EAP-TLS (§5.1) et l'exposition multi-machine de T35. **Ne pas exposer ce
  serveur sur TCP sans ces couches** (§5.3 : un trou non instrumenté est
  une porte).

## Feuilles et doctrine

- Chaque décision laisse une feuille `KindDecision` hash-only (§4.1, §6.2)
  : l'évaluation OPA laisse la sienne via T11 (record « TBPD1 ») ; les
  refus de niveau broker (entrée, traduction, enveloppe, émission) laissent
  la leur avec le même format de record et le même `jti` — tiré **avant**
  l'évaluation pour la traçabilité bout-en-bout (§4.3). **L'émission
  elle-même laisse aussi sa propre feuille broker**, sur le chemin allow :
  la feuille OPA de l'étape 4 ne prouve que l'évaluation de l'action, ni
  l'enveloppe (§4.1-bis — `OPAInput` ne transporte aucun champ quota) ni le
  fait qu'un jeton ait réellement été signé et remis ; sans elle, un
  passeport approuvé par l'enveloppe n'aurait aucune trace de registre
  portant son volume. Même doctrine « pas de preuve, pas d'accès » que
  T9/T11 : si cette feuille d'émission échoue, l'allow re-bascule en refus
  et le jeton n'est jamais rendu à l'appelant — sans libérer la réservation
  d'enveloppe déjà commise (la libérer ouvrirait un canal de sondage ;
  fail-closed va toujours vers plus de restriction, jamais moins).
- Le `jti` est aléatoire par construction (§4 du schéma) : le profil de
  déterminisme §11.3 porte sur les **verdicts et raisons**, pas sur les
  identifiants.
- Raisons stables, machine-readable : `request-invalid`,
  `epoch-unavailable` (faute, alarmée), `translation-failed`, `opa-*`
  (T11), `quorum-required`, `quorum-insufficient` (§7.5 — le gate trace en
  plus sa propre feuille `KindQuorum`), `envelope-deny`,
  `envelope-unverified`, `envelope-saturated`, `envelope-timeout`,
  `envelope-unreachable`, `envelope-error`, `envelope-bad-response`,
  `issuance-failed`, `leaf-write-failed`.
- Les fautes système (époque indisponible, émission impossible, feuille
  impossible, fautes d'enveloppe) déclenchent la couture d'alarme `OnTrip`
  vers T14 ; les verdicts sains (deny métier, refus de quorum, « je ne sais
  pas traduire ») non — même distinction que T11.

## Mesures

`Broker.Stats()` expose les compteurs (requêtes, émissions, refus, échecs
de traduction, refus de quorum, évaluations et refus d'enveloppe, fautes
d'émission et de feuille) — intrant du harnais de friction T27 (§9.1) et
de la supervision T34 (#60). La latence par étape est mesurable via `pep.OPADecision.Elapsed`
(évaluation) et `EnvelopeDecision.Elapsed` (enveloppe) ; la signature
Ed25519 a été mesurée ~70 µs par T8.
