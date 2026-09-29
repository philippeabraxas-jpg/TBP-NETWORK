# GDPR

**Status: Full**
**Source**: [issue #155](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/155)
**Reference**: EU Regulation 2016/679. Full treatment of the privacy strand left open by [SOC 2 (#154)](154-soc2.md).
**Last verified**: 2026-09-29

Legend: ✅ Covered · 🔴 Real gap (needs code; the row links the issue that tracks it) · ⚪ Not TBP's concern (the row says why and, for a deployment, how to close it). A combined status splits one control between what TBP covers and what stays with the deployer. See the [catalogue README](README.md).

## Principles and rights vs. TBP

| Provision | Content | Status | Detail |
|---|---|---|---|
| **Art. 5(1)(c)** — Data minimization | Collect/process only what's strictly necessary | ✅ | **TBP's best GDPR argument**: hash-only leaves (§6.2) never carry business content, only a salted hash — minimization isn't a bolted-on policy, it's structural. |
| **Art. 5(1)(e)** — Storage limitation | Don't retain beyond what's necessary | ✅ | `KindRetentionPurge` (T22, §6.2) makes telemetry-retention purges traceable (hash of the destroyed batch manifest). The audit chain itself is append-only by design and holds hashes, not content. **Note:** salted hashes remain pseudonymous data in the GDPR sense; the cell salt (`TBP_SALT`) never leaves the cell, and destroying it makes them irrecomputable (see Art. 17). |
| **Art. 5(1)(f)** — Integrity and confidentiality | Security of processing | ✅ | Same foundation as the rest of this series: HSM, mTLS, fail-closed. |
| **Art. 5(2)** — Accountability | Be able to demonstrate compliance | ✅ | The tessera audit chain *is* the demonstration — traceable, non-repudiable. |
| **Art. 17** — Right to erasure | Erase personal data on request | ⚪ | Since TBP never writes business content in clear text to its leaves, there is structurally nothing to erase in the audit trail for most cases. The remaining concern: an agent's `subject` MAY be a personal identity and it sits in clear text in `agents.json`. **To close:** (1) use pseudonymous subject identifiers, never a name or email; (2) to erase, remove the entry and restart `brokerd`; (3) if the leaves themselves must become unlinkable, destroy the cell salt, which makes their hashes irrecomputable for everyone including the operator — at the cost of correlating past decisions. The legal assessment is the controller's. |
| **Art. 12–22** — Access, rectification, portability, objection rights | Interface for exercising data-subject rights | ⚪ | TBP has no end-user surface — this is a layer upstream/downstream of TBP that must expose these rights, not TBP itself. |
| **Art. 25** — Data protection by design and by default | Privacy by design / by default | ✅ | **Second-best argument**: hash-only AND OPA's default-deny together are a textbook "privacy by design" case — protection isn't an opt-in feature, it's the system's DEFAULT behavior. |
| **Art. 33/34** — Breach notification (72h to the authority, without undue delay to data subjects) | Breach-notification process | ⚪ posture | Same gap as the CSF Respond function ([#153](153-nist-csf-800-53.md)): `OnTrip`/the T14 alarm is a real technical trigger, but there's no formal "personal-data breach" classification or notification workflow — TBP supplies the signal, not the regulatory procedure. **To close:** classify a personal-data breach in your own process and use the `OnTrip` alarm and the audit chain as detection and evidence; the notification workflow is the controller's. |
| **Art. 35** — Data Protection Impact Assessment (DPIA) | Prior privacy-risk evaluation | ⚪ | Same pattern as everywhere else (ISO 42001 A.5, ISO 23894, [#148](148-iso-iec-42001.md)/[#150](150-iso-iec-23894.md)): TBP consumes the result of an assessment (F/I/W class), never performs it itself. **To close:** the controller runs the DPIA and can cite the hash-only data flow of TBP as an input. |
| **Art. 6/7** — Legal basis, consent | Legal grounding for processing, consent management | ⚪ | Product/business decision, never an infrastructure-authorization feature. |
| **Art. 44–49** — Transfers outside the EU | Standard contractual clauses, adequacy decisions | ⚪ | Deployment/legal question, not runtime. |

---

## Summary

**TBP has two first-order GDPR arguments, already built for other reasons**: minimization (Art. 5(1)(c)) and privacy by design (Art. 25) are satisfied STRUCTURALLY by the hash-only + default-deny doctrine — not controls added to check a box, but properties of the architecture itself. Lead with these in any TBP GDPR documentation.

**Real point of attention**: an agent's `subject` in `agents.json`/the registry MAY constitute personal data depending on deployment context, with no dedicated withdrawal/revocation mechanism today — overlaps the governance gap already identified in [#143](143-owasp-llm-top10.md) (AST09.6, revocation process).

**Same "Respond" gap as [#153](153-nist-csf-800-53.md)**: breach notification — TBP has the trigger (`OnTrip`), not the regulatory process. Documented here as a deliberate posture, not fixed in code.
