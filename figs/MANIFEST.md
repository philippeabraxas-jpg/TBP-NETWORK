# Figures referenced by `docs/spec-v1.4.2.md`

No image file exists in this folder yet — the six figures below are
referenced by the technical note but still need to be produced. This
manifest lists what each one must show, based on the text surrounding it
in the spec, so that whoever draws (or generates) them starts from the
right content without having to re-read the whole document.

| File | Section | Expected content |
|---|---|---|
| `fig1_chaine.png` | §0 Summary | The end-to-end TBP governance chain: agent → translator → OPA (decision) → PEP (execution) → registry (proof) — the overview diagram everything else refers back to. |
| `fig2_handshake.png` | §3 Inter-entity handshake | The three handshake proofs in sequence: policy_id (rules), O(log n) consistency proof (history), verifier nonce → real OPA cycle → leaf → HSM signature (liveness). |
| `fig3_reseau.png` | §5.1 The wall and the switchboard | Network topology: NAC as switchboard, broker VLAN vs. captive VLAN, server wall (no direct client→server path), EAP-TLS sharing the handshake's PKI. |
| `fig4_registre.png` | §6 Two-tier registry | Cell chain (hot) → periodic inscription into the master chain (CT pattern/RFC 6962) → external anchoring (cold). |
| `fig5_passeport.png` | §4.1-bis Bounded-capacity passports | Temperature separation: counter at the PEP/terminator (execution) vs. egress envelope at the broker (issuance), with metadata telemetry as output. |
| `fig6_cles.png` | §7 Cluster: cells, epochs, mirrors, canary | Key and time hierarchy: controllers (m-of-n, HSM) → epoch token (TTL) → cell keys → action tokens (short TTL). |

Suggested format: versioned SVG source (`figs/src/`) + PNG export here, to
stay editable without depending on a proprietary tool. Palette and style:
see the "harmonized palette" note in the v1.4.1 changelog (§16) — to
define if no style guide exists elsewhere already.
