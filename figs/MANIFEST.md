# Figures referenced by `docs/spec-v1.4.2.md`

All six figures now exist as PNG (rendered from SVG source in `src/`).
This manifest still tracks what each one shows and where to find its
editable source, per the constructs each figure is drawing (box/arrow
mechanism diagrams and a sequence diagram, not decoration).

| File | Section | Source (editable) | Content |
|---|---|---|---|
| `fig1_chaine.png` | §0 Summary | `src/fig1_chaine.svg` | The end-to-end TBP governance chain: agent (probabilistic) → translator → OPA (decision) → PEP (execution) → registry (proof), with the deterministic/machine-level boundary marked explicitly. |
| `fig2_handshake.png` | §3 Inter-entity handshake | `src/fig2_handshake.svg` | Sequence diagram of the three handshake proofs between verifier and entity: policy_id, O(log n) consistency proof, nonce → OPA cycle → leaf → HSM signature — then the differentiated-treatment verdict (§3.3). |
| `fig3_reseau.png` | §5.1 The wall and the switchboard | `src/fig3_reseau.svg` | Network topology: NAC routing authenticated vs. unknown endpoints to the broker VLAN or the captive VLAN, the wall blocking any direct client→server path, EAP-TLS sharing the handshake's PKI. |
| `fig4_registre.png` | §6 Two-tier registry | `src/fig4_registre.svg` | Cell chains (hot) → periodic inscription into the master chain (CT pattern/RFC 6962, warm) → external anchoring (cold), with the bounded-lag threshold noted. |
| `fig5_passeport.png` | §4.1-bis Bounded-capacity passports | `src/fig5_passeport.svg` | Temperature separation: egress envelope counted at issuance (broker) vs. volume counted at execution (PEP/terminator), metadata telemetry feeding the registry, and the quota-overrun path. |
| `fig6_cles.png` | §7 Cluster: cells, epochs, mirrors, canary | `src/fig6_cles.svg` | Key/time hierarchy: controllers (m-of-n, HSM, long-lived) → epoch token (~60s TTL) → cell keys → action tokens (30–60s TTL, unique jti). |

**Regenerating a PNG after editing its SVG**: rendered via headless
Chromium (`--headless --screenshot`) at 2x scale for crisp text — no
external diagramming tool or library involved, hand-authored SVG only
(native shapes and `<text>`, no `<style>`/`<script>`, per the project's
"no proprietary tool dependency" goal already stated here). Any browser's
print/export also works if Chromium isn't available.

**Style**: dark ink (#1a1a1a) on white, one accent color (#1a5490) marking
the element the point of the figure hinges on, dashed strokes for
external/pending/restricted elements — consistent across all six so they
read as one system rather than six unrelated drawings.
