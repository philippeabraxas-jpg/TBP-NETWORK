# TBP compliance mapping

A gap analysis of TBP against 21 external security, AI-governance, and regulatory
frameworks — control by control, honest about what TBP covers, what it doesn't,
and why. Produced so this analysis stays visible on its own, rather than buried
inside closed GitHub issues: every fix below traces back to the catalog issue
that found the gap and the PR that closed it.

**Methodology**: each standard was read control-by-control (or layer/tactic/
function-by-function, depending on the framework's own shape) against TBP's
actual code, not its aspirations. Every ✅ cites the specific mechanism; every
🔴 gap is stated plainly and points to the issue that tracks it; a deliberate
design tradeoff (e.g. fail-closed over availability) is documented as such
rather than hidden. Frameworks that regulate an organizational process TBP
cannot itself embody (Govern, incident response, procurement) are marked ⚪ out
of scope rather than force-fit into a false ✅.

**Row legend.** Every row of every file is exactly one of:
- ✅ **Covered** — a mechanism in the code or a shipped rule pack, named in the row, with its limits.
- 🔴 **Real gap** — needs code; the row links the issue that tracks it. Nothing stays 🔴 without an issue.
- ⚪ **Not TBP's concern** — the control belongs to another layer (the executor, the OS, the deployer's PKI or change process, an organizational duty). A grey row that concerns a deployment says **why it is grey** and **what the deployer or operator does to close it** (*To close:*), so the catalogue doubles as a deployment checklist.
- A combined status such as `✅ files · ⚪ other backends` splits one control between what TBP covers and what stays with the deployer.

There is no "partial" status: a partial control is split into its ✅ part and its 🔴/⚪ part.

**File status** (aggregate per standard, derived mechanically from the rows —
`python3 tbp-compliance/check_catalog.py` enforces it):
- **Full** — no 🔴 row remains; everything applicable is ✅ or ⚪ with its guide.
- **Partial** — at least one 🔴 row (listed under "Open gaps that need code" below).
- **Not applicable** — the standard has no controls to catalog (terminology
  reference only).

## AI security & agentic-threat frameworks

| Standard | Status | File |
|---|---|---|
| OWASP Agentic Skills Top 10 (AST10) | Full | [142-owasp-agentic-skills-top10.md](142-owasp-agentic-skills-top10.md) |
| OWASP GenAI LLM Top 10 (2026) | Partial | [143-owasp-llm-top10.md](143-owasp-llm-top10.md) |
| CSA MAESTRO (7-layer threat model) | Full | [144-csa-maestro.md](144-csa-maestro.md) |
| MITRE ATLAS (16 tactics) | Partial | [145-mitre-atlas.md](145-mitre-atlas.md) |

## AI regulatory / governance frameworks

| Standard | Status | File |
|---|---|---|
| EU AI Act | Full | [146-eu-ai-act.md](146-eu-ai-act.md) |
| NIST AI RMF 1.0 (Govern/Map/Measure/Manage) | Full | [147-nist-ai-rmf.md](147-nist-ai-rmf.md) |
| ISO/IEC 42001:2023 (AIMS) | Full | [148-iso-iec-42001.md](148-iso-iec-42001.md) |
| ISO/IEC 22989:2022 (AI terminology) | Not applicable | [149-iso-iec-22989.md](149-iso-iec-22989.md) |
| ISO/IEC 23894:2023 (AI risk management) | Full | [150-iso-iec-23894.md](150-iso-iec-23894.md) |
| US federal AI directives (M-25-21 / M-25-22) | Full | [151-us-federal-ai-directives.md](151-us-federal-ai-directives.md) |

## General cybersecurity & privacy frameworks

| Standard | Status | File |
|---|---|---|
| ISO/IEC 27001/27002:2022 | Partial | [152-iso-iec-27001-27002.md](152-iso-iec-27001-27002.md) |
| NIST CSF 2.0 / SP 800-53 | Partial | [153-nist-csf-800-53.md](153-nist-csf-800-53.md) |
| SOC 2 (5 Trust Services Criteria) | Full | [154-soc2.md](154-soc2.md) |
| GDPR | Full | [155-gdpr.md](155-gdpr.md) |

## Supply-chain frameworks

| Standard | Status | File |
|---|---|---|
| SLSA v1.0 (build provenance) | Full | [156-slsa.md](156-slsa.md) |
| OWASP SCVS (component verification) | Partial | [157-owasp-scvs.md](157-owasp-scvs.md) |
| CIS Benchmarks | Full | [158-cis-benchmarks.md](158-cis-benchmarks.md) |

## Architecture-specific frameworks

| Standard | Status | File |
|---|---|---|
| NIST SP 800-207 (Zero Trust Architecture) | Partial (strongest match in the series) | [159-nist-800-207-zero-trust.md](159-nist-800-207-zero-trust.md) |
| IEC 62443 (OT/industrial) | Full | [160-iec-62443.md](160-iec-62443.md) |
| FIPS 140-3 (cryptographic module validation) | Full (documentary scoping only) | [161-fips-140-3.md](161-fips-140-3.md) |
| OWASP API Security Top 10 (2023) | Full | [162-owasp-api-security-top10.md](162-owasp-api-security-top10.md) |

## Recurring threads across the whole series

1. **The same structural gap, confirmed independently by seven frameworks**
   (AST10, LLM Top 10, MAESTRO, ATLAS, ISO 42001, ISO 27001, NIST CSF): TBP had
   no notion of an installable "skill"/tool with its own identity, provenance,
   and scope. Closed by `SkillRegistry`
   ([#165](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/165), PR
   [#166](https://github.com/philippeabraxas-jpg/TBP-NETWORK/pull/166)), on the
   same out-of-band, pinned pattern as `AgentRegistry` (#125). `risk_tier` is now
   a required field, enforced by the `tbp.pack.skill_tier` rule pack; per-skill
   credential isolation is grey (TBP holds no skill credential) with a guide
   for the deployer — see [#142](142-owasp-agentic-skills-top10.md).
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

## Open gaps that need code

Every 🔴 row in the catalogue, by the issue that tracks it. This list is the
catalogue's contribution to the backlog; when one of these is closed, its rows
move to ✅ in the same pull request.

| Issue | Gap | Rows |
|---|---|---|
| [#181](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/181) | Behavioural profile by sequence (salami / decomposition, cost anomalies, per-run cost cap, downstream monitoring) | [143](143-owasp-llm-top10.md), [145](145-mitre-atlas.md) Impact, [153](153-nist-csf-800-53.md) DETECT |
| [#86](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/86) | Operator console that renders the exact translated action before approval | [143](143-owasp-llm-top10.md) LLM06 human confirmation |
| [#192](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/192) | Measured boot does not cover the provisioning files (agents, operators, skills, keyrings, ano rules) | [152](152-iso-iec-27001-27002.md) configuration management, [159](159-nist-800-207-zero-trust.md) tenet 5 |
| [#193](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/193) | GitHub Actions referenced by tag, not by commit SHA | [157](157-owasp-scvs.md) build environment |

## Rule packs that close catalogue rows

The rows a Rego rule can close are closed by named, tested packs under
`policies/rego/` (documented in [`policies/README.md`](../policies/README.md)):

| Pack | Closes |
|---|---|
| `tbp.pack.agent_hardening` | agent memory files, credential stores, egress allowlist, command allowlist, explicit paths ([142](142-owasp-agentic-skills-top10.md) AST 1.6/3.3/3.4/3.6/3.7/3.8/5.4, [143](143-owasp-llm-top10.md) memory) |
| `tbp.pack.skill_tier` | `risk_tier` gating ([142](142-owasp-agentic-skills-top10.md) AST 4.5/9.2) |
| `tbp.pack.agent_scope` | per-agent action and resource allowlist ([143](143-owasp-llm-top10.md) LLM06) |

## Maintaining the catalogue

This folder is a living asset: it is only worth citing if it is current. Rules:

1. **Every pull request that changes what TBP covers updates the catalogue in
   the same PR** — a new mechanism moves its rows to ✅ (cite the mechanism and
   its limits); a new limit or a discovered gap adds or changes a row. The pull
   request template has a checkbox for this.
2. **No row without a decision.** A new control is ✅, 🔴 (with an issue) or ⚪
   (with *why grey* and, for a deployment, *To close:*). `check_catalog.py`
   fails the build on a partial row, a 🔴 without an issue, an empty ⚪, or a
   file status that does not follow from its rows.
3. **Update "Last verified"** in every file you re-read against the code. A
   status without a recent date is a claim nobody re-checked.
4. **Standards move.** When a standard publishes a new version or a regulation
   changes, re-read the file, add the new controls, and note the version in the
   header. Regulatory files (EU AI Act, US federal directives, GDPR) are due for
   a re-check at least every quarter.
5. **New standard = new file** numbered after the last one, added to the
   README tables, with its rows decided as above.

## Re-verification

Every file above carries a **Last verified** date. Regulatory texts move —
[#151](151-us-federal-ai-directives.md) documents a case where the originally
requested instruments (EO 14110, OMB M-24-10) were already repealed by the
time of analysis. Treat any file older than a few months as due for a
re-check before citing it externally, particularly the regulatory (not
technical-security) standards.
