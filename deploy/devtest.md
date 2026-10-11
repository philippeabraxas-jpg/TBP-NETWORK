# deploy/devtest.md — a DEV-TEST deployment: run it, attack it, do not trust it

_Version française : [devtest.fr.md](devtest.fr.md)._

> **Not for production.** Every key this makes is thrown away and lives on the same machine. It proves nothing
> about key custody, about separation between real people, or about a genesis ceremony. Use it on a clean
> virtual machine, with no real data and no real agent behind it.

One command sets up a scale-2 cell — `brokerd` and its OPA, the same chain [scale-2.md](scale-2.md) builds by
hand — so that you can run it, try to break it, and report what you find, without spending an afternoon on
key ceremonies first. The point is to test **the real thing**: the same binaries, the same code paths, the same
refusals.

## What is simplified, and what is not

| | In this deployment | Why it is safe to simplify, or not |
|---|---|---|
| Keys | generated for you, in one directory (0700) of the calling user | **Simplified.** Custody and the separation of real people are not tested here |
| Genesis | a manifest of three controller public keys, no ceremony, no HSM | **Simplified.** `topology = mono` has no epoch lease |
| Issuer key | a seed file (`TBP_ISSUER_SEED_FILE`) instead of an HSM | **Simplified, and the only development switch in use**: it is why `/etc/tbp/DEV_ENVIRONMENT` is created and why `brokerd` raises a high-priority alarm at every start |
| Rules | the example bundle of `policies/rego/`, restricted capabilities, **signed** | Same as production: OPA refuses an unsigned or altered bundle |
| Quorum | `k = 2` of `n = 3`, one spare | **Not simplified** |
| Operator keys | four keys with roles: two approve, one only cuts (`revoke`, `arbitrate`), one submits | **Not simplified**: roles, submitter ≠ approver, `k` approvals for class F and W |
| OPA ↔ `brokerd` | Unix socket, authenticated by the peer's UID | Same code path as production, **but both run as the same user**: that user can impersonate OPA |
| Provisioning witness | on: the scale and the trust files are attested at start | **Not simplified**: lowering `TBP_QUORUM_MIN` in the environment is refused |
| Network | nothing listens on TCP; Unix sockets in a 0700 directory | |

What it does **not** start: `pepd` on application servers, `supervisord`, `anod`, the mTLS listener and remote
agents (step 7 of [scale-2.md](scale-2.md)), and anything multi-cell. What it **cannot** tell you: whether your
key custody, your ceremony or your network isolation are sound.

## Before you start

- A clean Debian 12 virtual machine you can lose. **No real data, no real credentials, no route from it to
  anything you care about.** `init` refuses a machine that already holds `/var/lib/tbp`, or `/etc/tbp/brokerd.env`,
  `/etc/tbp/pepd.env` or `/etc/tbp/quorum-keyring.json`.
- A normal user (not root). `sudo` is used once, to write `/etc/tbp/DEV_ENVIRONMENT`. In a throw-away container
  you can allow root with `DEVTEST_ALLOW_ROOT=1`.
- `opa` (≥ 1.0), `openssl`, `jq`, `curl`, and either `go` (the version in `go.mod`) or the release binaries:
  `bash scripts/release/build.sh dist` (the script uses `dist/` when it finds the binaries there).

## Use

```bash
scripts/devtest/devtest.sh init     # keys, rules, signed bundle, environment — once
scripts/devtest/devtest.sh up       # OPA, then brokerd, in the background
scripts/devtest/devtest.sh demo     # 12 checks: what is refused, what is allowed, and why
scripts/devtest/devtest.sh status
scripts/devtest/devtest.sh down
scripts/devtest/devtest.sh reset    # stop, delete everything, remove the sentinel if this script made it
```

Everything lives in `$TBP_DEVTEST_HOME` (default `~/tbp-devtest`; keep the path short: `init` refuses one that
would push a socket path past the Unix limit):

| Path | What |
|---|---|
| `keys/controller-1..3.key` | the three controllers: any two sign a class-W action (`k = 2` of 3) |
| `keys/operator-1..4.key` | `operator-1`, `operator-2`: approve plans · `operator-3`: `revoke` and `arbitrate` only · `operator-4`: submits plans |
| `genesis/manifest.json`, `keys/quorum-keyring.json` | the public keys of the controllers |
| `opa/` | restricted capabilities, signing key, verification key, signed bundle, the OPA launch arguments |
| `brokerd.env`, `operators.json`, `agents.json` | the cell's settings; `agents.json` has `agent-f` (class F), `agent-i` (class I), `agent-w` (class W) |
| `run/` | the Unix sockets: `broker.sock` (agents, `POST /v1/actions`) and `broker-admin.sock` (operators) |
| `registry/`, `audit/` | the cell's log and the encrypted journal of cleartexts ([audit.md](audit.md)) |
| `log/` | `opa.log`, `brokerd.log` |

`demo` is the shortest path to see the cell work: an unknown agent and an agent with no plan are refused; a
class-I action is allowed after one signed plan and one operator's approval; a class-W action is refused with no
proof, refused with one controller, allowed with two, and the same proof does not work twice. It fails, with the
unexpected answer, if the cell behaves differently.

## Attacking it

Everything in [scale-2.md](scale-2.md) is written to be attacked. A few places to start, each with the refusal
the guides promise: lower `TBP_QUORUM_MIN` in `brokerd.env` and start (refused, `quorum-settings`); alter a byte of
the bundle, or re-sign it with another key (OPA does not start); approve a plan with the submitter's own key;
approve a class-W plan with one operator; replay a controller proof; sign a plan hash the broker did not seal
(`quorumproof planhash`); cut a plan with an approval signature (a revocation is signed differently). Refusals
leave leaves in the cell's log, which [audit.md](audit.md) shows how to verify.

The limits the project already knows are listed in the [README](../README.md) ("Honesty about where this
stands"), in [CHANGELOG.md](../CHANGELOG.md) and in [governed-acts.md](governed-acts.md): a finding that is one of them is
welcome as an ordinary issue; anything exploitable goes through [SECURITY.md](../SECURITY.md).

## What this deployment will not tell you

Because the controllers, the operators and the cell all sit under one user on one machine, a compromise of that
user is a compromise of every key. That is what a real deployment prevents with separate people and HSMs, and it
is outside what this setup can test. The same goes for anything that depends on `pepd` running on a server you
do not control, on the network, or on more than one cell.
