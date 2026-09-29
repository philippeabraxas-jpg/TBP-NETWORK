# US Federal AI Directives — M-25-21 / M-25-22

**Status: Full**
**Source**: [issue #151](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/151)
**Reference**: originally requested as EO 14110 / OMB M-24-10 — **both are repealed** (EO 14110 repealed by EO 14148 on 2025-01-28; OMB M-24-10/M-24-18 superseded in April 2025 by **M-25-21** — agency AI use — and **M-25-22** — agency AI acquisition). This catalog covers the currently-in-force instruments.
**Last verified**: 2026-09-29 — **regulatory texts move fast; re-verify before citing.**

Legend: ✅ Covered · 🔴 Real gap (needs code; the row links the issue that tracks it) · ⚪ Not TBP's concern (the row says why and, for a deployment, how to close it). A combined status splits one control between what TBP covers and what stays with the deployer. See the [catalogue README](README.md).

## M-25-21 — Federal agency AI use

| Requirement | Status | Detail |
|---|---|---|
| Inventory of AI use cases with risk categorization | ✅ | `AgentRegistry` (#125) does the equivalent PER AGENT (identity, resolved class) — not per use case, but the same out-of-band, pinned-inventory principle. |
| Designation of a Chief AI Officer | ⚪ | Organizational role. |
| "High-impact" designation for uses materially affecting rights/safety/service access/operations | ✅ | Directly overlaps TBP's class-W ("survival," irreversible actions) F/I/W model — same concept, different vocabulary. The class is a property of the agent in the registry, not of the action — see [#195](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/195). |
| Minimum risk-management practices for high-impact AI: testing, monitoring, transparency, human control | ✅ agents registered W · ⚪ class of the action (refused, #195) · ⚪ plan quorum (scale profile) | A near-identical restatement of EU AI Act Art. 12/13/14 already catalogued in [#146](146-eu-ai-act.md) — `QuorumGate` (human control), audit chain (monitoring/transparency), this repo's non-vacuous test discipline. Human control applies to agents registered class W; plan approval is a single attributed signature, the scale-1 profile — see [#195](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/195) and [#196](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/196). |
| Maximize use of American AI products | ⚪ | Geopolitical/procurement requirement, no technical relevance. |
| Compliance with OMB Circular A-130 privacy policy | ⚪ | Same angle as the hash-only doctrine (§6.2), but A-130 has its own specific federal requirements not verified in detail here. **To close:** the agency's privacy officer verifies the A-130 requirements; the hash-only doctrine is an input to that review. |

## M-25-22 — Federal agency AI acquisition

Almost entirely a PROCUREMENT text (how the US government buys AI), not a technical-controls framework — most of it is structurally out of TBP's scope:

| Requirement | Status | Detail |
|---|---|---|
| Vendor transparency on training data/model architecture | ⚪ | Concerns the model VENDOR, upstream of TBP. |
| Government rights over outputs/embeddings/fine-tuning artifacts | ⚪ | Contractual clause, not a technical control. |
| Anti-vendor-lock-in clauses | ⚪ | Procurement. |
| Mission-outcome-linked performance evaluation | ⚪ | Organizational/procurement. |
| Security requirements aligned with NIST guidance | ✅ | Points directly to NIST SP 800-53/CSF — see [#153](153-nist-csf-800-53.md) for the technical detail. |

---

## Summary

**Stay alert**: regulatory texts move fast (this document is direct proof — the originally-requested instruments were already repealed) — any TBP compliance doc citing government texts must carry a verification date and periodic review, never be treated as static.

**M-25-21 confirms, under different vocabulary, what [#146](146-eu-ai-act.md) (EU AI Act) already established**: TBP covers the test/monitoring/human-control triad for high-impact uses — a convergence point between two independent regulatory regimes (EU and US), reinforcing rather than duplicating the argument.

**M-25-22 confirms an entire framework can be almost entirely out of TBP's scope without that being a TBP defect** — it's a procurement text, not a technical-security one.
