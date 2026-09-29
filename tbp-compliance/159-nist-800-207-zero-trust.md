# NIST SP 800-207 (Zero Trust Architecture, 7 tenets)

**Status: Full** (strongest showing in the whole series — all 7 tenets ✅)
**Source**: [issue #159](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/159)
**Reference**: NIST SP 800-207 — 7 foundational tenets replacing perimeter trust with three pillars: verify explicitly, enforce least privilege, assume breach.
**Last verified**: 2026-09-29

## Scope note

First of four frameworks added after the initial 17-standard list closed ([#142](142-owasp-agentic-skills-top10.md)–[#158](158-cis-benchmarks.md)) — identified as directly relevant to TBP's actual architecture rather than AI in general. Unlike most AI-generic frameworks catalogued earlier, this one describes almost verbatim the architecture TBP ALREADY has, designed independently of any Zero Trust compliance goal.

Legend: ✅ Covered · 🔴 Real gap (needs code; the row links the issue that tracks it) · ⚪ Not TBP's concern (the row says why and, for a deployment, how to close it). A combined status splits one control between what TBP covers and what stays with the deployer. See the [catalogue README](README.md).

## The 7 tenets vs. TBP

| # | Tenet | Status | Detail |
|---|---|---|---|
| 1 | All data sources and computing services are resources | ✅ | The broker/OPA/registry are themselves treated as protected resources, never implicitly trusted — 0660 Unix-socket permissions, mTLS (#124): no internal component is "trusted because internal." |
| 2 | All communication is secured regardless of network location | ✅ | Direct, total match: mandatory mTLS for any network exposure (#124, `RequireAndVerifyClientCert`), Unix socket + `SO_PEERCRED` locally — no unauthenticated communication path exists, "internal" or not. |
| 3 | Access is granted per-session, never persistent | ✅ | TBP goes further than required: every `HandleAction` is re-authorized INDIVIDUALLY (no reusable session concept), and the issued token has a short TTL (30–60s, Issuer-bounded) — stricter than the tenet itself asks. |
| 4 | Access is determined by dynamic policy (identity, app/service state, behavioral/environmental attributes) | ✅ | Exactly the OPA evaluation with identity resolved by `AgentRegistry` (#125) + epoch/quorum state — never cached, re-evaluated on every request. |
| 5 | The enterprise monitors and measures the integrity/security posture of all assets | ✅ · ⚪ fleet policy | Measured boot (T31, §6.3, `KindManifest` leaves) and the OPA bundle revision-check (§92.A5) cover the posture of one cell's components; the provisioning files that carry the cell's trust are measured at each start too ([#192](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/192)); the supervisor's independent monitor and console (T34/T37; `cells.json` lists each cell's log and manifest directory) read every declared cell. **Why the fleet policy is grey:** alerting thresholds across a larger deployment are the operator's. **To close:** set your own alerting thresholds on the console's indicators. |
| 6 | Authentication/authorization are dynamic and strictly enforced BEFORE any access | ✅ | The broker's entire chain — nothing executes without passing through translator→OPA→quorum→contract, fail-closed at every step. |
| 7 | The enterprise collects information on asset/network/communication state for security posture improvement | ✅ | The tessera audit chain — already the most-cited strength across this whole series (Art. 12 in [#146](146-eu-ai-act.md), Art. 5(2) in [#155](155-gdpr.md)). |

---

## Summary

**Best score of the whole series**: all 7 tenets ✅ (tenet 5, posture of all assets, closed for the provisioning files by [#192](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/192); the fleet-wide alerting policy stays the operator's). Not a coincidence — TBP's "no direct client → server path" doctrine and Zero Trust start from the same premise (never trust a network path or an unverified identity), without either having been written with the other in mind.

**Strong recommendation**: this catalog should be the first cited in any TBP security/sales documentation — "Zero Trust architecture aligned with NIST SP 800-207" is a verifiable, largely-already-true claim, unlike several other frameworks in this series where TBP is only partial evidence in a larger file.

**One point to strengthen**: tenet 5 (fleet-wide posture) — the mechanism exists per-cell, not federated. Could overlap a future supervision-console extension (#86).
