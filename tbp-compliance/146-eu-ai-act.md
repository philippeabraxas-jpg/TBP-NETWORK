# EU AI Act

**Status: Partial**
**Source**: [issue #146](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/146)
**Reference**: EU Regulation 2024/1689 — Art. 5, 9, 10, 12, 13, 14, 15, 50. High-risk obligations fully apply from **2 December 2027**; Art. 50 (end-user transparency) in force since 2 August 2026.
**Last verified**: 2026-09-28

## Scope note — read this before the table

The Regulation classifies and regulates "AI systems" with a defined purpose (Annex III for high-risk), not generic infrastructure components. TBP is closer to a **technical component a deployer would use to demonstrate their own compliance** (logging, human oversight, robustness) than to an "AI system" under the Regulation itself — "is TBP a high-risk system?" isn't really a meaningful question; the right one is "does TBP help a deployer satisfy their Art. 9–15 obligations?". That framing is used throughout.

Legend: ✅ Covered/strong technical evidence · 🟡 Partial · 🔴 Real gap · ⚪ Out of TBP's scope

## Articles vs. TBP

| Article | Obligation | Status | Detail |
|---|---|---|---|
| **Art. 5** — Prohibited practices | Ban on manipulation, social scoring, emotion recognition at work/school, etc. | 🟡 | TBP neither defines nor detects a prohibited practice itself — that's a PRODUCT decision (what the agent may do). But OPA's default-deny is the right PLACE to technically encode such a ban if a deployment decides to — TBP provides the enforcement mechanism, not the classification. |
| **Art. 9** — Risk management system | Full-lifecycle process: identification, estimation, evaluation, mitigation, testing | 🟡 | TBP (fail-closed, class-W quorum, registry-resolved quota) is a PIECE of a risk-management system — technical evidence to cite in an Art. 9 file, never the risk-management system itself (a broader organizational process). |
| **Art. 10** — Data governance | Quality, relevance, bias of training/validation data | ⚪ | Structurally upstream of TBP — same reasoning as LLM02/LLM05 ([#143](143-owasp-llm-top10.md)): TBP never sees training data. |
| **Art. 12** — Record-keeping | Automatic, secure, traceable logging across the lifecycle | ✅ | **The strongest match in this whole catalog series.** TBP's tessera audit chain (§4.1, §6.2: hash-only leaves, master-chain anchoring, `KindDecision`/`KindTelemetry`/`KindEpoch`/`KindQuorum`/…) *is* automatic, secure logging by construction, not a bolted-on compliance add-on. |
| **Art. 13** — Transparency to deployers | Interpretable output, clear instructions for use | 🟡 | Stable machine-readable `Reason` codes (`opa-deny`, `quorum-required`, `agent-quota-exceeded`, …) give solid RUNTIME interpretability — but the instructions-for-use document itself (capabilities/limits documentation) remains a documentation deliverable, not a TBP property. TBP supplies the raw material, not the document. |
| **Art. 14** — Human oversight | Effective supervision, ability to intervene and block | ✅ | A direct, literal match: `QuorumGate` (class W, §7.5) requires k-of-n human operator co-signature BEFORE any irreversible action — exactly "meaningful human control, able to intervene and block the decision." |
| **Art. 15** — Accuracy, robustness, cybersecurity | Resist errors, misuse, adversarial attacks | 🟡 | The "robustness/cybersecurity" strand is strong (generalized fail-closed, non-extractable HSM §114, mTLS #124, signed and revision-checked OPA bundle §106/§92); the "accuracy" strand (did the model reason correctly?) is out of reach — TBP never judges reasoning quality, only the resulting action's policy conformance. |
| **Art. 50** — End-user transparency | Inform users they're interacting with AI; label deepfakes | ⚪ | A different layer: human-facing UI/UX obligation, not machine-to-infrastructure action authorization. TBP has no end-user surface — out of scope by construction. |

---

## Summary

**TBP's best EU AI Act audit argument**: Art. 12 (record-keeping) and Art. 14 (human oversight) are covered almost verbatim, by mechanisms designed before this analysis existed — the hash-only doctrine and class-W quorum answer the Regulation's text nearly word for word.

**Framing to document explicitly** (in any future `Compliance.md`/security overview): TBP is not "the AI system" under the Regulation — it's a component a deployer invokes to satisfy their OWN obligations. This distinction should be stated plainly to avoid anyone mistakenly seeking an "EU AI Act certification of TBP" rather than reusable technical evidence for THEIR OWN compliance file.

**No new SkillRegistry overlap here** — the EU AI Act doesn't address installable skills/packages, consistent with it being a regulatory framework, not a technical security one.
