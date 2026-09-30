# deploy/scales.md — security bricks per scale (issue #86)

_Version française : [scales.fr.md](scales.fr.md)._

TBP is deployed at several scales. It is **not rewritten** for each of them:
one code base, and a scale is a **setting of security bricks** — some on,
some off, some at a different strength. This page is the list. Every row
names the knob that exists today, so a profile is something you can read in
an env file, a signed bundle or a registry, never a second product.

Guides by scale: [scale-1.md](scale-1.md) (one machine, the administrator
alone). Scale 2 (small site) is tracked in #86; scales 3 and full follow the
multi-cell guides ([cellule.md](cellule.md), [superviseur.md](superviseur.md))
and the full-scale handshake (#33).

## Where a profile lives

A profile is **not a new file**. It is the set of values below, in the places
where the code already reads them. Consequence: nothing new to trust, nothing
new to measure — the provisioning witness (#192) already covers the keyrings
and registries, and the signed bundle already carries the Rego settings.

Not done yet: an audit leaf at startup that records the effective settings, so
that "which profile was this cell running on that day" is answered from the
log and not from an admin's memory. Tracked in #86.

## The bricks

| Brick | Knob | Scale 1 (admin alone) | Scale 2 (small site) | Scale 3 (multi-cell) | Full |
|---|---|---|---|---|---|
| Quorum for governed acts (posture, provisioning, measured boot, class W) | `TBP_QUORUM_MIN` + quorum keyring | **k = 1**, one administrator key | k ≥ 2 recommended | k-of-n, controllers in HSM | defined in the handshake (#33) |
| Topology / fencing | `TBP_TOPOLOGY` | `mono` (no epoch lease) | `mono` or `multi` | `multi`, epoch lease renewed m-of-n (#197) | `multi` |
| Broker (`brokerd`) | `TBP_BROKER_*` | absent | present | present, one per cell | present |
| mTLS network listener | `TBP_BROKER_TLS_*` | absent (Unix socket) | required if agents are remote | required, dedicated agent CA | required |
| Skill registry + tiers | `TBP_SKILL_REGISTRY_FILE`, bundle `require_skill_registry` | n/a (no broker) | recommended, **set `require_skill_registry`** | required | required |
| Per-agent scope | bundle `agent_scope.require_agent_scope` | n/a (no broker) | recommended | required | required |
| OPA fault handling | `TBP_OPA_TRIP_AFTER`, `TBP_OPA_AUTOCLEAR_PROBES` | defaults (3 / 3) | defaults | defaults; a second OPA backend is planned | defined in the handshake (#33) |
| Provisioning witness | `TBP_PROVISIONING_WITNESS_FILE` | required (admin signs a change) | required | required | required |
| Measured boot | `TBP_MEASURED_BOOT_*` | required | required | required | required |
| Supervisor / independent monitor | `superviseur.md` | absent | optional | required | required |
| Inter-cell encrypted transport | #187 | n/a | n/a | required | required |
| Inalienable rules | (to define) | to define | to define | to define | to define in the handshake (#33) |

`n/a` means the brick has nothing to attach to at that scale, not that it was
forgotten. "recommended" and "required" are this repository's guidance; the
code enforces the ones that have a knob that refuses to start without it.

## What no scale can switch off

These have no production off switch. The only bypasses are the
`*_DEV_UNSAFE` / `*_INSECURE_*_DEV` flags, which need the `DEV_ENVIRONMENT`
sentinel at a path hard-coded in the binaries (#113) and are therefore
refused in production:

- default-deny and fail-closed on any doubt;
- hash-only leaves with a salt that stays on the machine (§6.2);
- OPA mandatory, authenticated by the kernel, on a signed bundle whose
  revision is pinned and re-checked (#92, #106);
- restart = `refused` until a quorum reconfirms a posture (#93);
- a plan approval for classes F, I and W (class W adds the quorum);
- the provisioning witness and measured boot at startup (#112, #192).

This list is the starting point for the "inalienable rules" the full-scale
handshake will define; it is what exists in the code today, not a decision.
Whether a brick may be relaxed at a given scale is a decision recorded here,
per brick, in the PR that changes it.

## Known limit: the skill registry is per-deployment (#195)

An agent that is not routed through `brokerd` has no skill registry and no
`input.skill`; the skill-tier pack then says nothing. That is why
`require_skill_registry` is an explicit per-scale setting above and not a
default: turn it on wherever `brokerd` fronts the agents. There is no
escalation beyond the `risk_tier` floor for classes I and W.
