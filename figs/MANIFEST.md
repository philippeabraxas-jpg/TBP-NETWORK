# Figures referenced by `docs/spec-v1.4.5.md`

All six figures exist as PNG. This manifest tracks what each one shows,
per the constructs each figure is drawing (box/arrow mechanism diagrams
and a sequence diagram, not decoration) — useful if one is ever redrawn
from scratch.

| File | Section | Content |
|---|---|---|
| `fig1_chaine.png` | §0 Summary | The end-to-end TBP governance chain: agent (probabilistic) → translator → OPA (decision) → PEP (execution) → registry (proof), with the deterministic/machine-level boundary marked explicitly. |
| `fig2_handshake.png` | §3 Inter-entity handshake | Sequence diagram of the three handshake proofs between verifier and entity: policy_id, O(log n) consistency proof, nonce → OPA cycle → leaf → HSM signature — then the differentiated-treatment verdict (§3.3). |
| `fig3_reseau.png` | §5.1 The wall and the switchboard | Network topology: NAC routing authenticated vs. unknown endpoints to the broker VLAN or the captive VLAN, the wall blocking any direct client→server path, EAP-TLS sharing the handshake's PKI. |
| `fig4_registre.png` | §6 Two-tier registry | Cell chains (hot) → periodic inscription into the master chain (CT pattern/RFC 6962, warm) → external anchoring (cold), with the bounded-lag threshold noted. |
| `fig5_passeport.png` | §4.1-bis Bounded-capacity passports | Temperature separation: egress envelope counted at issuance (broker) vs. volume counted at execution (PEP/terminator), metadata telemetry feeding the registry, and the quota-overrun path. |
| `fig6_cles.png` | §7 Cluster: cells, epochs, mirrors, canary | Key/time hierarchy: controllers (m-of-n, HSM, long-lived) → epoch token (~60s TTL) → cell keys → action tokens (30–60s TTL, unique jti). |

**No editable source is kept in this repo** — the SVG sources used to
render these PNGs were removed after generation. Redrawing one means
starting over from the "Content" column above, not editing an existing
file.

**Style**: dark ink (#1a1a1a) on white, one accent color (#1a5490) marking
the element the point of the figure hinges on, dashed strokes for
external/pending/restricted elements — consistent across all six so they
read as one system rather than six unrelated drawings. Reproduce this
palette if redrawing any of them.
