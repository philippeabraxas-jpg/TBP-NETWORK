# EU AI Act

**Status: Partial**
**Source**: [issue #146](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/146)
**Reference**: EU Regulation 2024/1689 — Art. 5, 9, 10, 12, 13, 14, 15, 50. High-risk obligations fully apply from **2 December 2027**; Art. 50 (end-user transparency) in force since 2 August 2026.
**Last verified**: 2026-09-29

## Scope note — read this before the table

The Regulation classifies and regulates "AI systems" with a defined purpose (Annex III for high-risk), not generic infrastructure components. TBP is closer to a **technical component a deployer would use to demonstrate their own compliance** (logging, human oversight, robustness) than to an "AI system" under the Regulation itself — "is TBP a high-risk system?" isn't really a meaningful question; the right one is "does TBP help a deployer satisfy their Art. 9–15 obligations?". That framing is used throughout.

Legend: ✅ Covered · 🔴 Real gap (needs code; the row links the issue that tracks it) · ⚪ Not TBP's concern (the row says why and, for a deployment, how to close it). A combined status splits one control between what TBP covers and what stays with the deployer. See the [catalogue README](README.md).

## Articles vs. TBP

| Article | Obligation | Status | Detail |
|---|---|---|---|
| **Art. 5** — Prohibited practices | Ban on manipulation, social scoring, emotion recognition at work/school, etc. | ⚪ | TBP neither defines nor detects a prohibited practice itself — that's a PRODUCT decision (what the agent may do). But OPA's default-deny is the right PLACE to technically encode such a ban if a deployment decides to — TBP provides the enforcement mechanism, not the classification. **To close:** write the deployment's prohibitions as Rego rules in the signed bundle (the rule packs are a template) and record the decision in your AI Act file. |
| **Art. 9** — Risk management system | Full-lifecycle process: identification, estimation, evaluation, mitigation, testing | ⚪ | TBP (fail-closed, class-W quorum, registry-resolved quota) is a PIECE of a risk-management system — technical evidence to cite in an Art. 9 file, never the risk-management system itself (a broader organizational process). **To close:** cite TBP's evidence (audit chain, `BrokerStats`, the test suite, this catalogue) in your risk-management file; the process itself is the provider's. |
| **Art. 10** — Data governance | Quality, relevance, bias of training/validation data | ⚪ | Structurally upstream of TBP — same reasoning as LLM02/LLM05 ([#143](143-owasp-llm-top10.md)): TBP never sees training data. |
| **Art. 12** — Record-keeping | Automatic, secure, traceable logging across the lifecycle | ✅ | **The strongest match in this whole catalog series.** TBP's tessera audit chain (§4.1, §6.2: hash-only leaves, master-chain anchoring, `KindDecision`/`KindTelemetry`/`KindEpoch`/`KindQuorum`/…) *is* automatic, secure logging by construction, not a bolted-on compliance add-on. Since the plan-approval leaf records who approved (operator `kid`, expiry and signature, record `TBPL2`), an approval is attributable after the fact; leaves stay hash-only (§6.2), so the proof needs the holder of the cell salt (the cell's auditor). |
| **Art. 13** — Transparency to deployers | Interpretable output, clear instructions for use | ⚪ | Stable machine-readable `Reason` codes (`opa-deny`, `quorum-required`, `agent-quota-exceeded`, …) give solid RUNTIME interpretability — but the instructions-for-use document itself (capabilities/limits documentation) remains a documentation deliverable, not a TBP property. TBP supplies the raw material, not the document. **To close:** write the instructions-for-use document from the stable `Reason` codes and this catalogue. |
| **Art. 14** — Human oversight | Effective supervision, ability to intervene and block | ✅ agents registered W · 🔴 plans and class of the action | For actions of an agent registered **class W**, `QuorumGate` (§7.5) requires a k-of-n human operator co-signature BEFORE the action — meaningful human control, able to intervene and block the decision. **Limits found in review:** (1) the class comes from the agent registry (#125), not from the action, so an irreversible action requested by an agent registered F or outside F/I/W triggers no quorum unless the deployment ties risk to the action with skill `risk_tier` and `tbp.pack.skill_tier` (a `critical` skill refuses any agent below class W) — tracked in [#195](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/195); (2) approving a *plan* takes one operator signature, not a quorum (the approval is attributed in the audit leaf, `TBPL2`) — tracked in [#196](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/196). **To close (deployment):** register every agent that can perform an irreversible act as class W, set `require_skill_registry` in the bundle data, and give every irreversible skill `risk_tier: critical`. |
| **Art. 15** — Accuracy, robustness, cybersecurity | Resist errors, misuse, adversarial attacks | ✅ robustness · ⚪ accuracy | The "robustness/cybersecurity" strand is strong (generalized fail-closed, non-extractable HSM §114, mTLS #124, signed and revision-checked OPA bundle §106/§92); the "accuracy" strand (did the model reason correctly?) is out of reach — TBP never judges reasoning quality, only the resulting action's policy conformance. **To close (accuracy):** evaluate the model with your own evaluation suite; TBP judges policy conformance, never correctness. |
| **Art. 50** — End-user transparency | Inform users they're interacting with AI; label deepfakes | ⚪ | A different layer: human-facing UI/UX obligation, not machine-to-infrastructure action authorization. TBP has no end-user surface — out of scope by construction. |

---

## Summary

**TBP's best EU AI Act audit argument**: Art. 12 (record-keeping) and Art. 14 (human oversight) are covered almost verbatim, by mechanisms designed before this analysis existed — the hash-only doctrine and class-W quorum answer the Regulation's text nearly word for word.

**Framing to document explicitly** (in any future `Compliance.md`/security overview): TBP is not "the AI system" under the Regulation — it's a component a deployer invokes to satisfy their OWN obligations. This distinction should be stated plainly to avoid anyone mistakenly seeking an "EU AI Act certification of TBP" rather than reusable technical evidence for THEIR OWN compliance file.

**No new SkillRegistry overlap here** — the EU AI Act doesn't address installable skills/packages, consistent with it being a regulatory framework, not a technical security one.
