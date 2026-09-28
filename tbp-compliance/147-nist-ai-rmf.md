# NIST AI RMF 1.0 (Govern / Map / Measure / Manage)

**Status: Partial**
**Source**: [issue #147](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/147)
**Reference**: NIST AI 100-1 — voluntary US AI risk-management framework, 4 functions (Govern, Map, Measure, Manage), each broken into categories/subcategories in the companion Playbook.
**Last verified**: 2026-09-28

## Scope note

Like MAESTRO ([#144](144-csa-maestro.md)), this is not a technical-control checklist but an organizational PROCESS framework. The relevant question per function isn't "does TBP implement it?" but "which function does TBP provide usable technical evidence for, and which is structurally out of reach because it's a human process, not software?"

Legend: ✅ Covered/strong technical evidence · 🟡 Partial · 🔴 Real gap · ⚪ Out of TBP's scope

## The 4 functions vs. TBP

| Function | Covers | Status | Detail |
|---|---|---|---|
| **GOVERN** (cross-cutting) | Risk-management culture, accountability, policies, lifecycle oversight — 6 categories, 19 subcategories | 🟡 | An ORGANIZATIONAL process (roles, training, written policy) — no software "implements" Govern. What TBP contributes: the tessera audit chain assigns every decision to a traceable, non-repudiable leaf (§4.1) — technical PROOF of accountability, never governance itself. |
| **MAP** | Frame the system, its context, stakeholders, categorize risk upfront | ⚪ | Planning activity done BEFORE any TBP deployment — TBP doesn't categorize the risk of its own use case. (Meta note: this whole `tbp-compliance/` series is, in effect, a Map exercise — framing where TBP sits against each framework.) |
| **MEASURE** | Evaluate and quantify identified risks, test/verify/validate (TEVV) | 🟡 | `BrokerStats` (`Requests`, `Allows`, `Denies`, `QuorumDenies`, `PlanDenies`, `AgentDenies`, `EnvelopeDenies`, …) and the audit chain provide a real quantified signal on how often each control fires — usable measurement instrumentation, but TBP doesn't itself do the analysis/benchmarking this function requires. |
| **MANAGE** | Allocate risk-treatment resources, apply controls, prioritize response | ✅ | **This is where TBP lives.** Generalized fail-closed, class-W quorum, registry-resolved quota (#125), bundle revision-check (§92.A5) — all concrete risk TREATMENTS, not measurement or planning. TBP is an almost pure `Manage` component. |

---

## Summary

**Clear positioning**: of the 4 RMF functions, TBP is a near-pure **Manage** component, with useful by-products for **Measure** (stats/audit) and **Govern** (traceability/non-repudiation) — and structurally absent from **Map**, which stays human framing work that even this compliance series only tools, doesn't replace.

**Compared to the EU AI Act ([#146](146-eu-ai-act.md))**: both frameworks converge on the same message — TBP is reusable technical evidence within a broader risk-management program, never the program itself. The RMF formalizes this more explicitly by separating Govern/Map (human processes) from Manage (technical controls, where TBP lives).

**No new technical gap identified here** — expected, since this framework evaluates an organizational PROCESS, not precise software controls like AST10/LLM Top 10/ATLAS.
