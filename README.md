# TBP-NETWORK

Network-level implementation of the **Teleological Bounding Protocol (TBP)** —
attested governance of AI agent actions over a network, from a single
machine to enterprise deployments up to WWW scale.

> *« Existing access control decides whether you get in; TBP decides what
> you're allowed to do once inside — and proves it. We govern capabilities,
> not models. »*

**Never a partnership by trust — only by an attested handshake.** That's
what this repository is: the inter-entity handshake (spec §3) and
everything around it — NAC, PEPs, cell registries — that extends TBP's
governance from a single machine to a network of entities that have to
trust each other without simply trusting each other.

**Note on language**: the core specification (`docs/spec-v1.4.2.md`) and
glossary (`docs/glossaire.md`) are currently written in French — this
README and the configuration guidance below are in English so the repo is
navigable either way. Translating the full spec is on the list; until then,
this README summarizes enough to get oriented, and a native/fluent French
reader or a translation tool can go deeper on any section referenced below.

## Start here

The full specification is **[`docs/spec-v1.4.2.md`](docs/spec-v1.4.2.md)**
(French) — it is the source of truth for any design or configuration
decision in this repo. This README only summarizes what's needed to get
oriented; when in doubt, the spec governs.

Useful landmarks for reading it:
- **§1 Doctrine** — the eight non-negotiable rules.
- **§13 Implementation sequence** — the order to follow (HSM → OPA → PEP →
  NAC → translator), and the exact scope of pilot P1.
- **§9.1 Friction budget** — the latency and arbitration-rate thresholds
  that determine whether a TBP deployment is actually working; keep these
  in view for every configuration decision.
- **[`docs/glossaire.md`](docs/glossaire.md)** — one canonical term per
  concept, to be used consistently across the code and docs of this repo
  (see `CONTRIBUTING.md`).

## Relation to the main TBP repository

The protocol itself — specification, formal doctrine, adversarial audits,
core implementation (HSM signing, Merkle audit chain, OPA policy engine) —
lives in [Responsible-Alliance-Protocol](https://github.com/philippeabraxas-jpg/Responsible-Alliance-Protocol),
licensed Apache 2.0 (open). **This repository is the network-scale rollout**
of that same protocol: NAC, local PEPs, cell registries, the inter-entity
handshake — the pieces needed to take TBP from a single governed machine to
a governed network. "TBP is an open contribution" refers to the protocol
and its specification (open here too, see Licensing below); the
network-implementation *code* in this specific repo is closed during the
development/pilot phase (see Licensing) — a deliberate, temporary
distinction, not a contradiction: the doctrine, the rules, and how to
verify them are open now; the reference implementation of this particular
rollout opens once it's pilot-tested.

## Repository structure

```
docs/                 Specification (spec-v1.4.2.md), glossary, audits — currently French
figs/                  Figures referenced by the spec (see MANIFEST.md — none exist yet)
policies/
├── README.md          How to generate capabilities.json correctly
└── rego/               Illustrative example Rego policies
config/
├── nftables/           Local PEP redirection (§4.1)
├── freeradius/          802.1X / EAP-TLS (§5.1)
└── sysctl/               Generic kernel hardening
src/
├── pep/                 Local policy enforcement point (§4.1, §4.1-bis, §4.3)
├── telemetry/            Flow metadata, anti-dribble (§4.1-bis)
└── translator/            Translator runtime hardening (§4.5)
lab/                    docker-compose PoC + containerlab topology (TBD)
tests/
├── p1_friction/         Latency thresholds to respect (§9.1)
└── p2_redteam/           Attack scenarios to cover (§13)
.github/                Issue templates, CI (Rego + nftables lint)
```

**Current status: essentially a skeleton.** The spec is corrected and
complete; `config/` and `policies/` contain concrete starting points;
`src/`, `lab/` and `tests/` are, for now, READMEs describing the expected
scope (see §13 for the order to fill them in). Do not deploy `config/`
as-is — every file there says so explicitly, worth repeating here too.

## Configuration guidance — where to start

Based on the implementation sequence (§13) and the pilot P1 scope (§13,
§9.1: 1 server VLAN, Debian router, 2 cells, 802.1X, central registry,
measured user-experience regression = 0):

1. **Genesis and keys** (§7.2, §3.2) — before anything else: a genesis
   ceremony signed by the controller quorum (m-of-n, HSM), anchored
   out-of-band. Nothing in this repo replaces this step; it's procedural,
   not code.
2. **OPA** — install it, generate `policies/capabilities.json` following
   [`policies/README.md`](policies/README.md) (strip `http.send` and
   `time.now_ns` before any deployment, never after), start it with
   `lab/docker-compose.yml` to iterate on rules locally.
3. **PEP** — the first genuinely governed perimeter (§13). Read
   [`src/pep/README.md`](src/pep/README.md) for the decisions to make
   before writing any code, and [`config/nftables/pep-redirect.nft`](config/nftables/pep-redirect.nft)
   for the Debian-side network redirection. **Deploy in monitor mode
   first** (log, no blocking) — never `closed` on first rollout (doctrine
   §5.3).
4. **NAC in parallel** — [`config/freeradius/README.md`](config/freeradius/README.md):
   802.1X/EAP-TLS reusing the same PKI as the handshake (§3), fail-closed
   enforced at the switch level (not just on the RADIUS side), no
   RADIUS-assigned VLAN in v1.
5. **Host hardening** — [`config/sysctl/99-tbp-hardening.conf`](config/sysctl/99-tbp-hardening.conf)
   on every machine running a TBP component (broker, PEP, registry).
6. **Translator last** (§13) — once everything else is stable; see
   [`src/translator/README.md`](src/translator/README.md) for the
   expected runtime hardening (non-root, cap-drop, seccomp — distinct from
   `dm-verity`, which protects the image at rest, not the runtime).

At every step, measure against the friction budget (§9.1) — see
[`tests/p1_friction/README.md`](tests/p1_friction/README.md) for the exact
thresholds. The pilot fails if latency or arbitration rate exceed these
thresholds, even if everything else works.

## Licensing

Dual license, by subtree:
- **`docs/` and `figs/`**: [CC BY 4.0](docs/LICENSE) — free to share and
  adapt with attribution.
- **Everything else** (`config/`, `src/`, `policies/`, `lab/`, `tests/`,
  `.github/`): [all rights reserved](LICENSE) — closed during the current
  development/pilot phase; a more open license is planned once the
  network-rollout implementation is pilot-tested. The protocol itself —
  specification and core implementation — is open under Apache 2.0 in
  [Responsible-Alliance-Protocol](https://github.com/philippeabraxas-jpg/Responsible-Alliance-Protocol);
  only this specific network-rollout *code* is temporarily closed.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for what's open to contributions
right now (the documentation) and the rules to follow when editing the
spec (terminology normalization, verified citations, changelog).
