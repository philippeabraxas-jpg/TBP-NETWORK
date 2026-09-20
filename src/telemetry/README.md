# Metadata telemetry — anti-dribble (spec §4.1-bis)

Flow metadata exporters (IPFIX) for egress passing through a passport:
bytes per interval, destination, measurement window. Each record becomes
a leaf in the cell registry (§6).

**Mandatory doctrinal reminder** (§4.1-bis, already corrected once in
v1.4.2 to use the canonical term "passport" rather than "Sésame" — see
`docs/spec-v1.4.10.md` §16): **inspecting the content of passport flows is
prohibited.** Anti-dribble (detecting drip-feed, sub-threshold
exfiltration) relies *exclusively* on metadata post-processing — never on
DPI (deep packet inspection). Any implementation here that touches packet
content rather than metadata is off-doctrine, not just out of scope.

## État : exporteur IPFIX implémenté (T21)

`exporter.go` — décisions D17/D18/D19/D20 (plan et preuves sur l'issue
[#24](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/24)) :

- **Format : IPFIX v10** (D4 confirmée — extensible pour les champs TBP).
  Encodeur auto-porté, stdlib uniquement (D17) : template set (réémis à
  chaque message en v1) + data set ; champs standards `octetDeltaCount`,
  `ingressInterface`, `destinationIPv4Address`, `flowStart/EndMilliseconds`
  ; champs entreprise `tbp_jti`, `tbp_cell_id`, `tbp_resource`,
  `tbp_operation` (PEN **32473** = bloc documentation RFC 5615,
  placeholder en attendant l'assignation IANA). **Aucun champ de contenu
  n'existe dans le format.**
- **Source : compteur T12** (D18) — `LedgerSource(*pep.QuotaLedger)`.
  Le `PassportCounter` porte un totalisateur **monotone** des quanta
  acceptés : le delta par intervalle est toujours ≥ 0, jamais d'accès
  paquet, structurellement.
- **Chaque record = feuille `KindTelemetry` hash-only** (D19, §6.2) via
  `RecordSink` — la couture par laquelle **T22** interposera l'agrégation
  sans toucher l'exporteur.
- **« Métadonnées uniquement » prouvé par test structurel** (D20) :
  analyse AST du package — imports en liste blanche, aucune socket RAW ni
  écoute, `Record` sans champ de contenu.
- Le **rythme** n'est pas un champ du fil : il se dérive en post-traitement
  (`octetDeltaCount` / fenêtre) — affaire de T23.
- Records à delta nul non émis (§4.3 : pas d'inondation de zéros) ; la
  fenêtre de mesure chaîne les intervalles, le post-traitement lit les
  trous. Borne `maxRecordsPerMsg` = 64 par datagramme (excédent compté).

## État : pipeline d'agrégation implémenté (T22)

`aggregate.go` + `retention.go` — décisions D21–D26 (plan et preuves sur
l'issue [#27](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/27)) :

- **Couture `RecordSink`** (D21) : l'agrégateur se branche sur
  l'exporteur T21 sans le modifier.
- **Fenêtres tumbling (défaut 60 s), exactement une feuille par fenêtre
  scellée — y compris vide** (D22) : la continuité de la piste est un
  signal, un trou de fenêtre est une anomalie détectable par T23.
- **Agrégat hash-only « TBAG1 »** (D23, §4.5 par analogie) : flux,
  octets, top-k de destinations **hachées+salées**, racine de Merkle des
  engagements TBTM1 des records (le même engagement que la feuille record
  de T21 — l'auditeur rattache chaque record à sa fenêtre).
- **Rétention explicite et tracée** (D24, §6.2) : les bruts restent
  locaux, store borné (1440 lots = 24 h à 60 s) à TTL (défaut 24 h) ;
  chaque purge laisse une feuille `KindRetentionPurge` (manifeste
  « TBRP1 » haché+salé). Pas de trace ⇒ pas de destruction (§9.1).
- **Vérifiabilité auditeur** (D25) : `RetentionStore.Verify` rejoue
  Merkle → TBAG1 → hash salé tant que le brut existe ; `ErrBatchGone`
  après purge — c'est le sens de la rétention.
- Fail-closed et borné partout (D26) : store plein ⇒ `ErrStoreFull` +
  alarme `retention-store-full`, jamais de destruction pour faire de la
  place ; erreurs de feuille propagées à l'appelant (§5.3).

## Not implemented here (remaining placeholders)

- The "drip-feed" detection itself (**T23**) — thresholds, sliding
  windows, on aggregated metadata only.
