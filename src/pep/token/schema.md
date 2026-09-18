# Schéma formel du jeton signé TBP — **version 1**

| | |
|---|---|
| Statut | v1 — approuvé pour implémentation (T9) |
| Date | 2026-09-19 |
| Spec de référence | `docs/spec-v1.4.10.md` — §1, §3, §4.1, §4.1-bis, §4.3, §4.4(2), §4.5, §5.3, §7.2, §7.3, §9.1, §11.3, §12, §14 |
| Schéma machine | [`schema.cddl`](./schema.cddl) (CDDL, RFC 8610) |
| Tâche / issue | T8 / [#10](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/10) |

> **Document avant code.** Ce schéma est le contrat que le validateur (T9),
> le compteur de quota (T12) et le registre (T4) implémentent. Toute
> ambiguïté ici se paie en refactor du PEP, du registre et des tests — on ne
> code pas avant que ce document soit relu.

## 1 · Objet et portée

Deux objets, une seule enveloppe :

- le **jeton d'action** (§4.1) : signé Ed25519, TTL 30–60 s, portée =
  action + ressource, `jti` unique — délivré après décision OPA, validé
  par le PEP local (signature + fraîcheur + portée + non-consommation) ;
- le **passeport à quota** (§4.1-bis) : extension du jeton d'action pour
  les ouvertures de chemin lourd (session, tunnel, règle SDN), ajoutant le
  vecteur `(ressource, opération, volume_max, fenêtre, TTL, jti)`.

Hors de portée : le handshake inter-entités (§3, inter-domaines), le jeton
d'époque lui-même (§7.2 — produit par la genèse T3), le contenu métier des
actions (jamais en clair ici ni dans les feuilles, §4.5).

## 2 · Décision D2 — encodage : **CWT (RFC 8392) + COSE_Sign1 (RFC 9052), CBOR déterministe**

Trois candidats mesurés sur les critères de l'issue (outillage Ed25519,
taille, latence de vérification, déterminisme §11.3). Mesures du prototype
(sandbox CI x86-64, Go 1.24.5, jeu de claims complet — jeton d'action +
passeport, cf. §9) :

| Candidat | Taille fil | Vérif. Ed25519 | Sérialisation canonique | Outillage Go |
|---|---|---|---|---|
| **A. CWT + COSE_Sign1 + CBOR dét.** | **370 octets** | **~80 µs** | **native** (RFC 8949 §4.2.1) | `fxamacker/cbor/v2` v2.9.4 (MIT), `veraison/go-cose` v1.3.0 (MPL-2.0) |
| B. JWS compact + JSON (JCS) | 875 octets | idem (~72 µs hors enveloppe) | boulonnée (JCS RFC 8785) ou absente | `golang-jwt/jwt` (EdDSA) |
| C. Binaire custom | 340 octets | idem | ad hoc, à documenter soi-même | aucun — homebrew |

**Décision : A.** Motivations :

1. **La sérialisation canonique EST le format fil.** Le CBOR déterministe
   (tri des clés longueur-d'abord puis lexicographique, entiers en forme
   minimale, longueurs définies uniquement) rend le document signé unique
   bit-à-bit — c'est l'exigence §11.3, et c'est ce qui permet au registre
   (T4) de hacher des octets non ambigus. JSON n'a pas de forme canonique
   native : JCS est un correctif externe, et l'écart header/payload de JWS
   double les surfaces à figer.
2. **Taille** : 2,4× plus compact que JWS sur ce jeu de claims (370 vs
   875 octets) — pertinent pour le budget de latence tier 1 (§9.1) et pour
   la taille des feuilles qui porteront le `jti`.
3. **Latence** : vérification COSE complète (parse + Sig_structure +
   Ed25519) mesurée à ~80 µs, soit **~60× sous** le plafond de 5 ms (§9.1)
   et confortablement sous l'exigence T9 « validation < 1 ms hors OPA ».
4. **Pas de homebrew** : le custom ne gagne que 30 octets (8 %) et perd la
   séparation de domaine de `Sig_structure` (RFC 9052 §4.4), l'outillage
   audité et la vérifiabilité par un tiers — la doctrine §6 (« une preuve
   vérifiable par un tiers perd sa valeur si l'auditeur doit relire votre
   code ») s'applique aussi aux jetons. Écart accepté, standard retenu.
5. **Écosystème vérifié** : les deux dépendances sont disponibles, purs Go,
   compatibles avec le pin `go 1.24.0` du dépôt (elles exigent go ≥ 1.20 /
   ≥ 1.21), licences MIT / MPL-2.0. Ed25519 est l'algorithme -8 du registre
   COSE — §12 « Ed25519 partout » est satisfait nativement.

JWT/JWT-CWT mixtes et formats custom sont **rejetés** pour la v1.

## 3 · Enveloppe COSE_Sign1

```
COSE_Sign1 = [
  protected   : bstr .cbor { 1: -8, 4: kid },   ; alg = EdDSA, kid
  unprotected : {},                              ; vide — tout est protégé
  payload     : bstr .cbor tbp-claims,           ; CDDL §4-§5, CBOR dét.
  signature   : bstr .size 64                    ; Ed25519 sur Sig_structure
]
```

- **alg** : `EdDSA` (-8), Ed25519 — aucun autre algorithme accepté (§12).
- **kid** : `bstr .size 16` = `SHA-256(clé publique Ed25519 du broker)[0:16]`.
  Résolution dans le **trousseau épinglé** de la cellule (genèse T3,
  `pubkeys/*.hex`) — « jamais par nom, toujours par signature » : le jeton
  ne transporte **aucune** clé publique, aucune URL de clé, aucun `jwk`
  embarqué (un tel matériel = rejet).
- **Sig_structure** (RFC 9052 §4.4) : contexte `"Signature1"`, aucun
  externe AAD. C'est la séparation de domaine — un jeton TBP ne peut pas
  être re-signé dans un autre contexte COSE ni vice versa.
- **unprotected vide** : tout attribut non protégé = rejet (fail-closed).

## 4 · Champs du jeton d'action (payload CWT)

Clés 1/2/4/6/7 : registre CWT IANA. Clés négatives : usage privé TBP.
**Toute clé inconnue = rejet** (fail-closed §1) — un jeton ne peut pas
passer de contrebande dans un champ que le validateur ignorerait.

| Clé | Nom | Type CDDL | Présence | Contraintes | Réf. |
|---|---|---|---|---|---|
| 1 | `iss` | `tstr .size (1..255)` | requis | identifiant de la cellule émettrice = origin du registre (T4, ex. `tbp/registry/cell-alpha-01`) | §6 |
| 2 | `sub` | `tstr .size (1..255)` | requis | entité gouvernée (identité du handshake §3) | §3 |
| 4 | `exp` | `uint` | requis | fin de validité, secondes unix | §4.1 |
| 6 | `iat` | `uint` | requis | émission, secondes unix ; **30 ≤ `exp`−`iat` ≤ 60** | §4.1 |
| 7 | `cti` | `bstr .size 16` | requis | **jti** — 128 bits tirés crypto à l'émission, unique ; porté par chaque feuille d'exécution | §4.1, §4.3 |
| −1 | `policy_id` | `bstr .size 32` | requis | SHA-256 du bundle de règles P sous lesquelles l'entité opère — le même hash que le handshake et l'ancrage de bundle | §3, §7.4 |
| −2 | `action` | `tstr .size (1..255)` | requis | action autorisée, **produite par le traducteur**, jamais déclarée par l'agent | §4.1, §4.5 |
| −3 | `resource` | `tstr .size (1..1024)` | requis | ressource cible exacte | §4.1 |
| −4 | `class` | `uint .lt 4` | optionnel | 0 = F (financier), 1 = I (infrastructure), 2 = W (survie), 3 = hors F/I/W ; **absent ⇒ W** (défaut fail-closed) | §5.3, §1 |
| −5 | `object_seal` | `bstr .size 32` | optionnel | hash objet/champ/valeur — présent = object-capability scellée ; le PEP revalide le sceau à l'exécution | §4.4(2) |
| −6 | `epoch` | `uint` | requis | N de l'époque d'émission ; révocation = nouvelle époque ⇒ jetons de l'ancienne morts | §7.2, §7.3 |
| −9 | `v` | `1` | requis | version du présent schéma (§8) | — |

Notes de conception :

- **TTL (§4.1)** : double contrainte — `exp − iat ∈ [30, 60]` s à
  l'émission, et `iat ≤ now ≤ exp` à la validation (`now` = horloge NTS,
  état vérifié par T13 : `STA_UNSYNC` ⇒ mode dégradé explicite).
- **jti** : 128 bits aléatoires (crypto/rand). À 10⁶ jetons par cellule et
  par fenêtre, la probabilité de collision d'anniversaire est ≈ 10⁻²⁷ ;
  et une collision éventuelle **fait échouer fermé** (le second jeton est
  pris pour un rejeu → refus + feuille), jamais l'inverse.
- **`class` absent ⇒ W** : un émetteur qui omet la classe obtient le
  traitement le plus contraignant (arbitrage + quorum, §7.5) — jamais un
  passage facilité.
- **`epoch`** : le PEP connaît l'époque courante (T29) ; `epoch` du jeton
  ≠ époque courante ⇒ rejet. C'est le fencing §7.2 appliqué aux jetons
  d'action, et le mécanisme de mort des jetons à la révocation (§7.3).
- **Taille maximale du jeton fil** : 1 024 octets ; au-delà = rejet
  (borne DoS, même motif que le cache anti-replay borné de T10).

## 5 · Extension passeport (§4.1-bis) — clé −7 `quota`

Toute ouverture de chemin lourd est un passeport : le même jeton, augmenté
d'une clé `quota`. Le vecteur complet `(ressource, opération, volume_max,
fenêtre, TTL, jti)` est formé ainsi :

| Champ du vecteur | Source | Type CDDL |
|---|---|---|
| `ressource` | `quota.1` | `tstr .size (1..1024)` |
| `opération` | `quota.2` | `tstr .size (1..64)` |
| `volume_max` | `quota.3` | `uint` (octets) |
| `fenêtre` | `quota.4` | `uint .gt 0` (secondes) |
| `TTL` | **hérité de `exp` (clé 4) du jeton englobant** | — |
| `jti` | **hérité de `cti` (clé 7) du jeton englobant** | — |

Le lien cryptographique exigé par §4.1-bis est **structurel** : le quota
vit dans le payload signé — il ne peut être ni détaché du jeton, ni
modifié hors bande, ni porté par une règle. Un passeport se valide comme
un jeton d'action, plus les contraintes `quota` ; son compteur (T12)
décrémente `volume_max` dans `fenêtre`, une session = un terminateur,
dépassement = coupure propre + refus + feuille portant le `jti`.

**Proscription absolue (§4.1-bis)** : aucune inspection du contenu des
flux du passeport — le schéma ne prévoit donc **aucun** champ de contenu,
de payload réseau ou d'échantillon. L'anti-dribble relève exclusivement
des métadonnées de flux (T21/T23).

## 6 · Sérialisation canonique (profil §11.3)

Le payload et les en-têtes protégés sont encodés en **CBOR déterministe**
(RFC 8949 §4.2.1, équivalent RFC 7049 §3.9) :

1. clés de map triées **longueur d'abord, puis lexicographiquement** (les
   clés entières courtes précédent donc les négatives à deux octets) ;
2. entiers et longueurs en **forme minimale** ;
3. chaînes de **longueur définie** uniquement (indefinite-length interdit) ;
4. **aucun** flottant, **aucune** étiquette (tag) CBOR dans le payload ;
5. texte UTF-8 valide.

Conséquence : deux émetteurs conformes produisent les **mêmes octets** pour
les mêmes claims, et le hash des feuilles (T4) porte sur une forme unique.
Vérifié au prototype : 1 000 sérialisations successives du même jeu de
claims ⇒ octets identiques.

## 7 · Contrat de validation (pour T9)

Ordre des contrôles au PEP ; **chaque rejet produit une feuille portant le
`jti`** (allow aussi — §4.1) ; tout écart = refus, jamais de passage
silencieux (§1, `src/pep/README.md`) :

1. **Format** : COSE_Sign1 bien formé, ≤ 1 024 octets, `unprotected` vide,
   `alg = -8` ;
2. **Schéma** : payload conforme à `schema.cddl` — clés inconnues, types,
   tailles, `v = 1` (CBOR déterministe, décodage strict, clés dupliquées
   interdites) ;

   > **Note d'implémentation (T9) — rien de ceci n'est le comportement par
   > défaut de `fxamacker/cbor/v2`.** Un `Unmarshal` nu accepte
   > silencieusement les clés dupliquées (dernière valeur gagnante, aucune
   > erreur) et les items de longueur indéfinie ; il n'a de plus aucune
   > notion du jeu de clés fermé de `schema.cddl` et laisse donc passer
   > toute clé inconnue sans erreur — vérifié empiriquement contre
   > `fxamacker/cbor/v2` v2.9.4. Le « décodage strict » exigé ici n'est
   > donc PAS une propriété acquise en choisissant CBOR : T9 doit
   > explicitement construire son `DecMode` avec
   > `DupMapKey: cbor.DupMapKeyEnforcedAPF` et
   > `IndefLength: cbor.IndefLengthForbidden`, **et** rejeter par un
   > contrôle dédié toute clé décodée hors de l'ensemble fermé
   > `{1, 2, 4, 6, 7, −1, −2, −3, −4, −5, −6, −7, −9}` (`schema.cddl`
   > n'est pas exécuté comme validateur au chemin chaud — le budget de
   > latence §9.1 l'exclut — ce contrôle de clés doit donc être écrit à la
   > main, pas délégué à un validateur CDDL générique) ;
3. **Clé** : `kid` résolu dans le trousseau épinglé de la cellule ;
4. **Signature** : Ed25519 sur la `Sig_structure` — « jamais par nom,
   toujours par signature » ;
5. **Fraîcheur** : `30 ≤ exp−iat ≤ 60` et `iat ≤ now ≤ exp` (horloge NTS,
   état vérifié par T13) ;
6. **Époque** : `epoch` = époque courante (§7.2/§7.3) ;
7. **Portée** : `action` et `resource` du jeton == action et ressource de
   la requête, **re-validées indépendamment d'OPA** (§4.5) ;
8. **Sceau** : si `object_seal` présent, re-hash objet/champ/valeur de la
   requête et comparaison (§4.4(2)) ;
9. **Non-consommation** : `cti` absent du cache anti-replay (T10), puis
   consommé.

La politique (`policy_id`) est opposée au bundle chargé localement : un
jeton émis sous un autre jeu de règles est rejeté (cohérence avec §7.4).

## 8 · Revue croisée

| Besoin | Ce que ce schéma garantit |
|---|---|
| **T9** (validateur) | contrat complet §7 ci-dessus ; vecteur d'exemple §9 (clé publique = vecteur de test RFC 8032, reproductible) ; latence mesurée 80 µs ≪ 1 ms exigée |
| **T10** (anti-replay) | clé de cache = `cti` (16 octets fixes) ; fenêtre bornée par `exp` ; saturation = fail-closed (README PEP) |
| **T12** (quota) | vecteur §5 complet sans duplication : compteur indexé par `jti`, borné par `volume_max`/`window_s`, TTL = `exp` ; un terminateur par session |
| **T4/T22** (feuilles) | chaque feuille d'exécution porte `jti` (hex de `cti`) dans son payload hash-only ; le CBOR déterministe rend le hash non ambigu (§6) |

## 9 · Annexe — vecteur d'exemple (informatif, reproductible)

Jeton complet (370 octets fil), signé avec la **clé de test n° 1 du
RFC 8032 §7.1** (publique par construction, aucune valeur de production) :

- seed : `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`
- clé publique : `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`
- claims (décodés) :
  `iss="tbp/registry/cell-alpha-01"`, `sub="spiffe://tbp.example/agent/claude"`,
  `iat=1758264000` (2025-09-19T06:40:00Z), `exp=1758264060` (+60 s),
  `cti=0123456789abcdeffedcba9876543210`, `policy_id=00…00`,
  `action="http.send"`, `resource="https://api.example.com/v1/messages"`,
  `class=1` (I), `object_seal=00…00`, `epoch=7`, `v=1`,
  `quota={resource idem, operation="POST", volume_max=1048576, window_s=60}`.
- Ed25519 étant déterministe (RFC 8032), ce vecteur se régénère à
  l'identique :

```
d28455a20127045021fe31dfa154a261626bf854046fd227a0590114ad01781a7462702f72656769737472792f63656c6c2d616c7068612d30310278217370696666653a2f2f7462702e6578616d706c652f6167656e742f636c61756465041a68ccfafc061a68ccfac007500123456789abcdeffedcba987654321020582000000000000000000000000000000000000000000000000000000000000000002169687474702e73656e6422782368747470733a2f2f6170692e6578616d706c652e636f6d2f76312f6d6573736167657323012458200000000000000000000000000000000000000000000000000000000000000000250726a401782368747470733a2f2f6170692e6578616d706c652e636f6d2f76312f6d657373616765730264504f5354031a0010000004183c280158408428028bfc398b7d02f8eec0aca8c2f5995d1c77559cdc28fce82d4e1bcd073cf2db81d86294a19d2939f776062f0095fe1ff305ecea2275ac483dd5b04cbe07
```

## 10 · Versioning et évolution

- `v` (clé −9) est **obligatoire** ; v1 = le présent schéma.
- Toute modification non compatible (champ requis ajouté, type ou clé
  changé, sémantique modifiée) ⇒ `v+1` et nouveau document ; un validateur
  ne supporte que des versions explicitement listées — version inconnue =
  rejet (fail-closed).
- Ajout rétrocompatible possible en v1 : uniquement des clés privées
  **optionnelles** nouvelles — et encore : les validateurs v1 rejetteront
  ces jetons (clé inconnue), donc tout ajout est de fait incompatible et
  exige `v+1`. Règle simple : **on ne touche pas v1, on écrit v2**.

## 11 · Non-buts

- Aucun contenu métier en clair — ni ici ni dans les feuilles (§4.5, RGPD
  §6.2) ; le `jti` et les hash suffisent à l'audit.
- Aucune inspection de contenu des flux passeport (§4.1-bis).
- Aucune confiance TOFU dans du matériel de clé embarqué (§3) : le
  trousseau est épinglé à la genèse.
- Ce schéma ne couvre ni le handshake inter-entités (§3), ni le jeton
  d'époque (§7.2, genèse T3), ni les feuilles du registre (T4).

---

### Preuves d'implémentabilité (jointes à la livraison T8)

Mesures reproductibles (prototype Go 1.24.5, sandbox CI x86-64) :

- tailles fil : CWT/COSE/CBOR **370 o** · JWS/JSON 875 o · custom 340 o ;
- vérification COSE complète : **~80 µs** (Ed25519 nu ~72 µs) — budget
  tier 1 < 5 ms (§9.1) respecté avec une marge ~60× ;
- déterminisme : 1 000 marshal CBOR canoniques ⇒ octets identiques ;
- `schema.cddl` : syntaxe validée contre la **grammaire ABNF officielle**
  de RFC 8610 (dépôt cbor-wg/cddl) ;
- vecteur §9 : instance CBOR validée contre les contraintes du CDDL par
  décodage strict (clés inconnues, tailles, ranges) — **nominal conforme,
  3 falsifications rejetées** (clé inconnue, jti tronqué, TTL 3 600 s) ;
- signature du vecteur vérifiée avec la clé publique RFC 8032 annoncée.
