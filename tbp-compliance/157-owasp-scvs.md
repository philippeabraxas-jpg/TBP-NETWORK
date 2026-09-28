# OWASP SCVS (6 control families)

**Status: Full**
**Source**: [issue #157](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/157) · fix: [issue #170 / PR #171](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/170)
**Reference**: OWASP Software Component Verification Standard (SCVS) — 6 control families (Inventory, SBOM, Build Environment, Package Management, Component Analysis, Pedigree & Provenance), 3 increasing rigor levels.
**Last verified**: 2026-09-28

## Scope note

Like [SLSA (#156)](156-slsa.md), SCVS evaluates TBP's OWN dependency chain (the Go module and its dependencies), not the skills TBP would authorize — complementary to, not redundant with, the `SkillRegistry` gap.

Legend: ✅ Covered/strong technical evidence · 🟡 Partial · 🔴 Real gap · ⚪ Out of TBP's scope

## The 6 families vs. TBP

| Family | Content | Status | Detail |
|---|---|---|---|
| **Inventory** | Tracking of all components/dependencies | 🟡 | `go.mod` provides a trivial direct/indirect dependency inventory via standard Go tooling — no FORMAL inventory process documented beyond that. |
| **SBOM** | Published software bill of materials | ✅ | **Fixed** — the `sbom` CI job (`lint.yml`) generates a CycloneDX SBOM via `cyclonedx-gomod` (pinned `v1.12.0`) and publishes it as a build artifact (#170, PR #171). |
| **Build environment** | Securing where/how the build runs | 🟡 | Same as SLSA L1/L2 ([#156](156-slsa.md)): hosted GitHub Actions, no additional hardening. |
| **Package management** | Registry vetting, dependency-resolution policy | ✅ | **Underrated strength**: `go.sum` pins the cryptographic hash of EVERY dependency, verified on every build against the module checksum database — a real supply-chain integrity control, already active just from correct use of Go modules, no extra configuration. |
| **Component analysis** | Dependency vulnerability scanning (SCA) | ✅ | **Fixed** — the `govulncheck` CI job (`lint.yml`) runs `govulncheck ./...` (pinned `v1.8.0`, same doctrine as the OPA version pin) (#170, PR #171). |
| **Pedigree & provenance** | Traceability of each component's origin | ✅ | Directly overlaps [SLSA (#156)](156-slsa.md), now resolved (L3 reached via `slsa-github-generator`, #174/PR #175) — same status here. |

---

## Summary

**Positive discovery**: `go.sum` already does, for free, a good part of what SCVS asks for "Package management" — one more case (like Go modules, `DisallowUnknownFields`, or the language's own structure) where the project's ecosystem choice brings native compliance without dedicated configuration.

**Two concrete gaps, both fixed**: SBOM generation (`cyclonedx-gomod`) and `govulncheck ./...` vulnerability scanning — both added to `lint.yml` (#170, PR #171).

## Closing note for the 16-standard first wave (#142–#157)

This catalog closed the first requested set of 16 frameworks. Threads running through it, all now resolved:

- **The same structural gap confirmed seven independent times** — no notion of "skill"/installable tool — closed via `SkillRegistry` ([#165](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/165), PR #166), on the same pattern as `AgentRegistry` (#125).
- **Two concrete, low-effort supply-chain gaps specific to TBP itself** — build provenance ([SLSA, #156](156-slsa.md)) and SBOM/vulnerability scanning (here) — both fixed.
- **A recurring posture gap, never a defect** — TBP always supplies the signal (`OnTrip`, `Reason` codes, stats), never the response PROCESS (incident, regulatory notification) — consistent with being an enforcement point, not a governance platform.
- **Two design arguments worth leading with** — the hash-only doctrine (§6.2) for GDPR minimization/privacy-by-design, and the class-W quorum (§7.5) for EU AI Act Art. 14 / M-25-21 human control.
