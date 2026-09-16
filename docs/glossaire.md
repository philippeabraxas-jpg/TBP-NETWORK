# TBP normalization glossary

Quick-reference extract of §14 from [`spec-v1.4.6.md`](./spec-v1.4.6.md) (French) —
that file remains the source of truth; this one exists to be linked/grepped
without reopening the whole technical note. One canonical term per concept;
synonyms found in upstream documents (network manifesto, deployment
references, discussions) are mapped onto it — **the code and documentation
of this repository must use the "Canonical term" column**, never a
synonym, including in comments and variable/field names where reasonable.

| Canonical term (French) | English gloss | Mapped synonyms | Definition |
|---|---|---|---|
| cellule | cell | TBP Cellule, enclave, edge | broker + local registry + own policies; per-cell state |
| superviseur | supervisor | TBP Supervisor, core, egress | a cell with an extended perimeter + the master registry; never a black box |
| maîtresse | master chain | master chain, chaîne centrale | aggregation of cell heads, anchored |
| collection référencée | referenced rule collection | règles ABC (standard), profils | public rules, versioned, hashed, pinned |
| règles propres | own rules | règles XYZ, règles maison | local signed rules, undisclosed |
| passeport | passport | sésame, capacité, token de session | a token with a quota (resource, operation, volume, window, TTL, jti) |
| traitement différencié | differentiated treatment | couloir surveillé, verdict binaire | attested / strict / refused depending on the presented state |
| époque | epoch | epoch, fencing, jeton d'autorité | signed authority period, TTL, revocable |
| traducteur | translator | garde sémantique, traducteur local | the local AI producing the action actually executed |
| manifeste | manifest | état attesté, measured state | the measured vector of the governed stack (§6.3) |
| trou instrumenté | instrumented hole | capteur, canal instrumenté | a path outside the wall whose telemetry feeds the registry |

**Adding a term**: edit the §14 table in `spec-v1.4.6.md` first (it's the
source), then mirror it here. The two tables must stay word-for-word
identical (the "English gloss" column above is this file's own addition
for readability and is not part of the source table).
