# TBP compliance mapping

A gap analysis of TBP against 21 external security, AI-governance, and regulatory
frameworks — control by control, honest about what TBP covers, what it doesn't,
and why. Produced so this analysis stays visible on its own, rather than buried
inside closed GitHub issues: every fix below traces back to the catalog issue
that found the gap and the PR that closed it.

**Methodology**: each standard was read control-by-control (or layer/tactic/
function-by-function, depending on the framework's own shape) against TBP's
actual code, not its aspirations. Every ✅ cites the specific mechanism; every
🔴/🟡 gap is stated plainly, including when it's a deliberate design tradeoff
(e.g. fail-closed over availability) rather than an oversight. Frameworks that
regulate an organizational process TBP cannot itself embody (Govern, incident
response, procurement) are marked ⚪ out of scope rather than force-fit into a
false ✅.

**Status legend** (aggregate per standard — see each file for the item-by-item
breakdown):
- **Full** — no known real gap remains; everything applicable is ✅, or the
  framework is structurally almost entirely outside TBP's scope with the one
  applicable item resolved.
- **Partial** — a mix of ✅/🟡, and/or at least one open 🔴/documented-posture
  item not covered by any fix yet.
- **Not applicable** — the standard has no controls to catalog (terminology
  reference only).

## AI security & agentic-threat frameworks

| Standard | Status | File |
|---|---|---|
| OWASP Agentic Skills Top 10 (AST10) | Partial | [142-owasp-agentic-skills-top10.md](142-owasp-agentic-skills-top10.md) |
| OWASP GenAI LLM Top 10 (2026) | Partial | [143-owasp-llm-top10.md](143-owasp-llm-top10.md) |
| CSA MAESTRO (7-layer threat model) | Partial | [144-csa-maestro.md](144-csa-maestro.md) |
| MITRE ATLAS (16 tactics) | Full | [145-mitre-atlas.md](145-mitre-atlas.md) |

## AI regulatory / governance frameworks

| Standard | Status | File |
|---|---|---|
| EU AI Act | Partial | [146-eu-ai-act.md](146-eu-ai-act.md) |
| NIST AI RMF 1.0 (Govern/Map/Measure/Manage) | Partial | [147-nist-ai-rmf.md](147-nist-ai-rmf.md) |
| ISO/IEC 42001:2023 (AIMS) | Full | [148-iso-iec-42001.md](148-iso-iec-42001.md) |
| ISO/IEC 22989:2022 (AI terminology) | Not applicable | [149-iso-iec-22989.md](149-iso-iec-22989.md) |
| ISO/IEC 23894:2023 (AI risk management) | Partial | [150-iso-iec-23894.md](150-iso-iec-23894.md) |
| US federal AI directives (M-25-21 / M-25-22) | Partial | [151-us-federal-ai-directives.md](151-us-federal-ai-directives.md) |

## General cybersecurity & privacy frameworks

| Standard | Status | File |
|---|---|---|
| ISO/IEC 27001/27002:2022 | Full | [152-iso-iec-27001-27002.md](152-iso-iec-27001-27002.md) |
| NIST CSF 2.0 / SP 800-53 | Partial | [153-nist-csf-800-53.md](153-nist-csf-800-53.md) |
| SOC 2 (5 Trust Services Criteria) | Partial | [154-soc2.md](154-soc2.md) |
| GDPR | Partial | [155-gdpr.md](155-gdpr.md) |

## Supply-chain frameworks

| Standard | Status | File |
|---|---|---|
| SLSA v1.0 (build provenance) | Full | [156-slsa.md](156-slsa.md) |
| OWASP SCVS (component verification) | Full | [157-owasp-scvs.md](157-owasp-scvs.md) |
| CIS Benchmarks | Full | [158-cis-benchmarks.md](158-cis-benchmarks.md) |

## Architecture-specific frameworks

| Standard | Status | File |
|---|---|---|
| NIST SP 800-207 (Zero Trust Architecture) | Partial (strongest match in the series) | [159-nist-800-207-zero-trust.md](159-nist-800-207-zero-trust.md) |
| IEC 62443 (OT/industrial) | Partial | [160-iec-62443.md](160-iec-62443.md) |
| FIPS 140-3 (cryptographic module validation) | Full (documentary scoping only) | [161-fips-140-3.md](161-fips-140-3.md) |
| OWASP API Security Top 10 (2023) | Full | [162-owasp-api-security-top10.md](162-owasp-api-security-top10.md) |

## Recurring threads across the whole series

1. **The same structural gap, confirmed independently by seven frameworks**
   (AST10, LLM Top 10, MAESTRO, ATLAS, ISO 42001, ISO 27001, NIST CSF): TBP had
   no notion of an installable "skill"/tool with its own identity, provenance,
   and scope. Closed by `SkillRegistry`
   ([#165](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/165), PR
   [#166](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/166)), on the
   same out-of-band, pinned pattern as `AgentRegistry` (#125). Some
   `SkillRecord` extensions remain open (`risk_tier`, per-skill credential
   isolation) — see [#142](142-owasp-agentic-skills-top10.md).
2. **Three low/medium-effort, TBP-specific supply-chain gaps, all fixed**:
   build provenance ([SLSA](156-slsa.md), #174/PR #175), SBOM + vulnerability
   scanning ([SCVS](157-owasp-scvs.md), #170/PR #171), host-hardening
   documentation ([CIS](158-cis-benchmarks.md), #172/PR #173).
3. **One real security gap found on code already in production, fixed**: the
   `subject` accepted by `POST /v1/actions` wasn't bound to the
   mTLS-authenticated transport identity — BOLA/Broken Authentication
   ([OWASP API Security Top 10](162-owasp-api-security-top10.md), #163/PR
   #164).
4. **A recurring posture, documented rather than "fixed"**: TBP always
   supplies the trigger/signal (`OnTrip`, `Reason` codes, audit leaves) but
   never the incident-response or regulatory-notification PROCESS — consistent
   with being a fail-closed enforcement point, not a governance or detection
   platform. See NIST CSF Respond ([#153](153-nist-csf-800-53.md)), GDPR Art.
   33/34 ([#155](155-gdpr.md)), IEC 62443 FR6 ([#160](160-iec-62443.md)).
5. **A recurring, deliberate tradeoff, documented rather than "fixed"**: the
   generalized fail-closed doctrine prioritizes safety over availability —
   stated explicitly wherever an availability-focused criterion applies (SOC 2
   [#154](154-soc2.md), IEC 62443 FR7 [#160](160-iec-62443.md)) so it reads as
   a design choice, not a resilience shortfall.
6. **Two design arguments worth leading with in any pitch or audit**: the
   hash-only leaf doctrine (§6.2) for data minimization / privacy-by-design
   (GDPR Art. 5(1)(c)/25) and for confidentiality/DLP (ISO 27001, SOC 2); and
   the class-W quorum (§7.5) for human-oversight requirements (EU AI Act Art.
   14, M-25-21, NIST CSF PROTECT).
7. **The single best framework match**: [NIST SP 800-207 Zero
   Trust](159-nist-800-207-zero-trust.md) — 5 of 7 tenets direct ✅, designed
   independently of any Zero Trust compliance goal.

## Re-verification

Every file above carries a **Last verified** date. Regulatory texts move —
[#151](151-us-federal-ai-directives.md) documents a case where the originally
requested instruments (EO 14110, OMB M-24-10) were already repealed by the
time of analysis. Treat any file older than a few months as due for a
re-check before citing it externally, particularly the regulatory (not
technical-security) standards.
