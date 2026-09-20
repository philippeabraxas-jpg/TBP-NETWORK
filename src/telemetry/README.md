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

## Not implemented here (remaining placeholders)

- Aggregation pipeline before writing to the registry (**T22**) — the
  `RecordSink` seam is ready (§4.5: "aggregates + corpus hash — content
  never in the clear" applies here by analogy).
- The "drip-feed" detection itself (**T23**) — thresholds, sliding
  windows, on aggregated metadata only.
