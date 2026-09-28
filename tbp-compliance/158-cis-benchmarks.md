# CIS Benchmarks (Docker/Kubernetes/OS)

**Status: Full** (scope: a documented deployment prerequisite, not a TBP feature)
**Source**: [issue #158](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/158) · fix: [issue #172 / PR #173](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/172)
**Reference**: CIS Benchmarks — secure baseline configurations for systems/containers (Docker: 7 sections, 94 controls; Kubernetes: control plane, API server, kubelet, etc.)
**Last verified**: 2026-09-28

## Scope note

Unlike every other framework in this series, this one has **no control that belongs in the broker's code**: CIS Benchmarks configure the OPERATING SYSTEM, the DOCKER DAEMON, or the KUBERNETES CLUSTER that HOSTS a service — never the application logic running inside it. TBP is neither a container runtime nor an orchestrator; there is literally nothing to implement in `src/broker`, `src/pep`, or Rego rules to "satisfy" a CIS benchmark.

Legend: ⚪ Out of TBP's scope · ✅ Prerequisite documented

| CIS domain | Status | Detail |
|---|---|---|
| Host configuration (kernel, file permissions) | ✅ | **Fixed** — explicit recommendation of the CIS Debian Linux Benchmark as a host-hardening prerequisite (see below). |
| Docker daemon / images / container runtime | ⚪ | TBP neither requires nor ships containerization as its primary deployment mode (`deploy/*.md` documents Debian machines, not containers) — the `lab/docker-compose.yml` PoC mentioned in the repo layout is a demo environment, not the reference deployment mode. |
| Kubernetes control plane / API server | ⚪ | TBP doesn't run natively on Kubernetes today — not applicable. |

## The one actionable point

**Fixed** (#172, PR #173) — `deploy/cellule.md`, `deploy/cellule.fr.md`, `deploy/serveur.md` and `deploy/serveur.fr.md` now explicitly reference the [CIS Debian Linux Benchmark](https://www.cisecurity.org/benchmark/debian_linux) as a host-hardening prerequisite in their existing system-hardening sections, exactly on the model of the NAC 802.1X section already present in `router-debian.md`. No code change — a doctrinal addition to existing documentation, verified via `deploy/selftest/check_steps.py`.

---

## Summary — closing note for the second wave (#159–#162)

Together with #142–#157, this closes the full 21-standard catalog series. Of the four concrete, low/medium-effort technical gaps found across all 21 frameworks — `SkillRegistry`, SLSA, SCVS, CIS — all four are now fixed and merged (#165–#166, #174–#175, #170–#171, #172–#173).
