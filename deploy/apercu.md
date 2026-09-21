# deploy/apercu.md — overview: what, where, why, requirements

_Version française : [apercu.fr.md](apercu.fr.md)._

This document is the **entry point** of a TBP-NETWORK deployment: what
gets deployed, where each piece goes, why it exists, and what is needed
before starting. It synthesizes; the per-machine guides
([router-debian.md](router-debian.md), [cellule.md](cellule.md),
[serveur.md](serveur.md), [superviseur.md](superviseur.md)) execute.
When in doubt, the spec ([`docs/spec-en-v1.0.md`](../docs/spec-en-v1.0.md))
governs — and `deploy/selftest/` decides: a guide that drifts from the code
breaks there, not at the operator's site.

## Why — the doctrine in five points

1. **Never by trust, always by verifiable proof** (§1, §3):
   admission of an entity to the network happens through an attested
   handshake, not by reputation or by a "trusted" segment.
2. **Every decision leaves a leaf** (§4.1), and the leaf is
   **hash-only** (§6.2): the registry proves without revealing — the salt
   stays with the producer, never in a registry.
3. **Fail-closed everywhere** (§1): unreachable OPA, desynchronized clock,
   missing anchor, exhausted quota ⇒ traced and alarmed refusal. A silent
   hole is a fault, not a tolerance.
4. **Monitor before closed** (§5.3): the closed posture is not installed,
   it is earned — §9.1 measurement first, observation window, quorum
   to switch ([monitor-to-closed.md](monitor-to-closed.md)).
5. **A cell is cattle, never a trust root** (§7.1):
   governance keys live on HSM at genesis; cells
   verify and enforce, they hold nothing sovereign.

## What — the components and their provenance

| Component | Role | Provenance |
|---|---|---|
| NAC router | 802.1X/EAP-TLS (same PKI as the §3 handshake), VLANs, nftables walls | `config/freeradius/`, `config/nftables/` — **to adapt**, never copy (D99) |
| Cell | `brokerd` (§5.1 entry point), `pepd`, tessera registry, OPA, epoch tracker | `src/broker/`, `src/pep/`, `src/registry/`, `src/cluster/` — Go binaries from the repo |
| Application server | Application (PostgreSQL, …) + acceptance PEP via ITS cell | `src/pep/` (+ `src/pep/postgres-extension/` for the in-process PEP, §4.4) |
| Supervisor | Master chain (per-epoch anchors), independent monitor + console (`supervisord`), genesis | `src/registry/` (anchoring), `src/supervision/`, `scripts/genesis/` (HSM) |
| Translator | local AI producing the action — hardened runtime, controlled degradation, quality measurement | `src/translator/` (T24, T25, T26) — **optional, last** (§13) |
| Protocol core | HSM signer, Merkle audit chain, OPA policy engine | `tbp4.2.1/` submodule — frozen pointer, never modified here |

What the repo does NOT provide: the genesis ceremony itself
(procedural, §7.2/§3.2 — the tooling is in `scripts/genesis/`), the
site addressing plan, the production PKI, the translator's native
corpora (to be built at the pilot, §15).

## Where — P1 pilot topology and flows

Segments (§5.1, to adapt — `config/nftables/router-p1.nft` is the
starting point):

| VLAN | Role | Doctrine |
|---|---|---|
| 10 | servers + cells | governed traffic (PEP/broker) |
| 20 | authentication | EAP/RADIUS only |
| 33 | IoT / MAB | instrumented channel — NEVER silent |
| 66 | captive | **default VLAN** (failure / no auth) |
| 77 | remediation | revoked certificate, unreachable OCSP/CRL |
| 99 | management | out-of-production administration |

Machines (P1 §13: 1 server VLAN, Debian router, **2 cells**,
802.1X, central registry): 1 router, 2 cells (VMs), 1 application
server, 1 supervisor (independent VM + HSM).

Decision flow: agent → **broker** of its cell (Unix socket, v1) →
translator (`structured`) → OPA (restricted capabilities §12) →
class W quorum if required (§7.5) → plan contract if sealed (§4.2) →
CWT/COSE Ed25519 token → **PEP** in front of the resource (validation,
anti-replay, quota, fail-closed) → action. Every step leaves a leaf in
the **cell's registry**; anchors rise to the supervisor's **master chain**,
which the **independent monitor** re-reads in verified mode
(ChainWatcher: signed checkpoint + Merkle consistency) without ever
writing to it. The server only accepts via ITS cell's broker (§5.1);
no direct client → server path.

Custody: no governance key outside its role — the full
matrix is in [README.md](README.md) (decision D97): controller
keys on HSM only, `cell_log.key` in ITS cell, leaf salt with the
producer, monitor key with the supervisor.

## Requirements

### Hardware — minimal P1 pilot

- 1 router: Debian 12, **≥ 2 interfaces** (dedicated or VM); an
  802.1X switch for the real NAC — otherwise `lab/containerlab/` to exercise it.
- 2 cell VMs (a single cell can defer fencing, a pilot
  cannot — §7.2/§13).
- 1 application server host (PostgreSQL if the PEP extension is targeted).
- 1 supervisor VM + **HSM** (SoftHSM tolerated in DEV only — never a
  governance root, §12).

### Software — every machine

- Debian 12 (bookworm, the repo's target), **Go ≥ 1.24**, **OPA ≥ 1.0**,
  python3 — verified in common step 1 of [README.md](README.md).
- Router: `nftables`, `freeradius`, `hostapd`.
- Supervisor: `softhsm2-util` (dev) or the HSM's PKCS#11 (prod).
- Server: PostgreSQL + dev headers if the extension is compiled.
- Hardening: `config/sysctl/99-tbp-hardening.conf` (to adapt to the
  site) on every machine running a TBP component.

### Procedural — before any command

- **Genesis first**: m-of-n quorum of controllers on HSM, anchored
  out-of-band. Nothing in the repo replaces this ceremony; its
  artefacts (`manifest.json`, `pubkeys/*.hex`, `epoch0.json`) are the
  verifiable prerequisite of the first cell step.
- Addressing plan settled; `config/` is to **adapt**, not to copy.
- D97 custody understood and accepted: `*.pem`, `*.key`,
  `config/freeradius/certs/` (example to adapt, never copy),
  `policies/capabilities.json` are never committed (gitignored).

### Human

- The guides are written for a **non-author operator**: every step
  carries a verifiable prerequisite, an observable success criterion and an
  "On failure: STOP". Never continue on a red prerequisite.
- The monitor → closed switch requires a **quorum**: a single operator
  cannot close the network (demonstrated by the selftest: 1 signer →
  403, quorum → 200).

## In which order — §13 instantiated (D98)

```
0. common prerequisites       deploy/README.md (common steps)
1. genesis (supervisor, HSM)  scripts/genesis + superviseur.md step 1
2. fencing (epoch trackers)   cellule.md — exercised by the selftest (2 cells)
3. OPA + registry             cellule.md steps 3-6 (restricted capabilities §12)
4. PEP / broker (MONITOR)     cellule.md step 7, serveur.md — nothing but monitor
5. router NAC                 router-debian.md — LAST network link
6. translator (optional)      src/translator/README.md — last, always
```

The order is not cosmetic: governance (1-2) precedes policy
(3), which precedes application (4), which precedes network (5). Deploying
the NAC before fencing would admit clients without epoch
governance — exactly the defect fencing exists to prevent.

Before touching a real machine: `bash deploy/selftest/selftest.sh`
— **82 controls** (real single cell, 2-cell fencing, real
brokerd/supervisord daemons), fail-closed, JSON report in
`deploy/selftest/out/`. Then the per-machine acceptance checklists
([checklists/](checklists/)).

## Pilot success criteria

- Green selftest and acceptance checklists signed on each machine.
- **§9.1 friction budget met** ([`tests/p1_friction/`](../tests/p1_friction/)):
  measured user-experience regression = 0 — the pilot fails if
  latency or the arbitration rate exceed the thresholds, even if
  everything else works.
- Zero untraced action: every decision produces a verifiable leaf;
  every alarm has a recipient.
- The closed switch happens after the observation window, on a fed
  §9.1 measurement, by quorum ([monitor-to-closed.md](monitor-to-closed.md)).

## Honest limits (as of — 2026-09-22)

- The translator's **native corpora** remain to be built at the pilot
  (§15); the measurement chain (replay, per-class metrics, "TBTM1"
  leaf) is delivered and tested on a sample mini-corpus.
- `brokerd` v1 only accepts the `structured` translator: the natural
  language / human escalation path is not wired (the degradation
  controller, on the other hand, is delivered and tested).
- Inter-domain is deferred by the spec itself (§13, issue #33).
- The registry's bounded-async durability (T38) is delivered (PR #78,
  merged).
- `config/` is never deployed as-is — always adapt;
  every file says it, this document repeats it.
