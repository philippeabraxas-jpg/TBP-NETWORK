# deploy/dev-test/site — three machines: M1 the cell, M2 a server, M3 an agent

_Version française : [site.fr.md](site.fr.md)._

> **Not for production.** Every key this makes is thrown away, and the cell's governance keys all sit on M1. Use
> three virtual machines you can lose, on a private network, with no real data and no real agent behind them.

This is the functional test of a scale-2 site. The question is not whether the code is sound — the CI and the
selftest already ask that — but **whether the whole thing works across machines**: an agent enrolled by its
certificate, a decision by the cell, a token checked by the enforcement point on a server, the server's posture
governed by the controllers. And, because it is the real thing, whether you can break it.

One script, `scripts/devtest/site.sh`, deploys each machine with one command; this page says what each machine is
for, why, how to deploy it, what to test and where to attack. A one-machine quick start, for looking at the cell
alone, is [solo.md](solo.md).

## The three machines

```
 M3  the agent                      M1  the cell                         M2  an application server
 curl + the agents' certificates    OPA + brokerd, the keys              OPA + pepd + the application

 1. ask for a decision ─────────►   :8443, mutual TLS
                                     decides, signs a token
 2. the token ◄─────────────────
 3. present the token ─────────────────────────────────────────────────►  :9000 the application
                                                                           asks pepd (127.0.0.1:8443)
                                                                           acts only if pepd forwards
 4. the answer ◄───────────────────────────────────────────────────────

 Administration — operators and controllers — is done on M1, locally.  Packs travel by scp: M1 → M2, M1 → M3.
```

| | M1 — the cell | M2 — the application server | M3 — the agent |
|---|---|---|---|
| What runs | OPA, `brokerd` with an mTLS listener | OPA, `pepd`, a small application | nothing: `curl` and certificates |
| Its job | decides who may do what, and signs a token for it | checks the token before the application acts | acts as an agent: asks, then presents what it got |
| What it holds | the controllers' and operators' keys, the CAs, the issuer key | public material only: the issuer's public key, the controllers' public keys, the signed rules | its agents' certificates and keys |
| What it never holds | — | **no governance key**, no CA key | no governance key, no CA key |
| What you do there | enrol, sign plans, sign the controllers' proofs | close and reopen `pepd` with those proofs | request, replay, forge, impersonate |

**Why these three.** They are the smallest set that exercises what a one-machine test cannot: *enrolment* (M3's
agents are bound to the certificates M1 issued), a decision *over the network* (mutual TLS), and *enforcement* by a
different machine from the one that decided (M2 trusts M1 only through what M1's pack pinned: it does not call M1 at
all). A real scale-2 site is the same shape with several servers and several agent hosts: M1 is *the* cell, M2 is one
of the application servers, M3 is a host of agents.

## The network

Put the three machines on one private network (a cloud VPC, or a host-only network). Only these flows are needed:

| From → to | Port | What | Open to |
|---|---|---|---|
| M3 → M1 | 8443/tcp | decisions, mutual TLS | M3's address only |
| M3 → M2 | 9000/tcp | the application | M3's address only |
| you → each | 22/tcp | ssh and `scp` | your address only |

Nothing else, and **nothing from the Internet**. Use your provider's firewall or security groups for it. `pepd`
listens on `127.0.0.1:8443` on M2, so it is not reachable from M3; the cell's administration is a Unix socket on M1,
not a network port. After deploying, check what each machine really listens on: `scripts/devtest/site.sh m1
listeners` (and `m2`, `m3`).

## Before you start

| Machine | Needs |
|---|---|
| M1 | Debian 12, a user with `sudo`, `git curl jq openssl`, **OPA**, **Go** (the version in `go.mod`) — or the release binaries |
| M2 | Debian 12, `git curl jq openssl python3` — nothing else: its binaries come from M1's pack |
| M3 | Debian 12, `git curl jq perl` |

We have not measured the smallest machine that works; our runs used 4 CPUs and 16 GB for everything. Each `report`
records yours, so please tell us. We have not yet timed a cold deployment on three fresh machines either: that
timing is part of what we ask.

## Deploy

Replace `<M1>`, `<M2>` by the machines' **private** addresses on your network. `--env` is a free label (for example
`provider, size, region`) that your reports repeat: it is how we tell environments apart.

**On M1** — the cell:

```bash
sudo apt-get update && sudo apt-get install -y git curl jq openssl ca-certificates
# OPA, the version CI uses, checked against its published checksum
curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.20.2/opa_linux_amd64_static
curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.20.2/opa_linux_amd64_static.sha256
sha256sum -c opa_linux_amd64_static.sha256          # must say: opa_linux_amd64_static: OK
sudo install -m 0755 opa_linux_amd64_static /usr/local/bin/opa
# Go, at least the version in go.mod (Debian 12's own package is 1.19, too old). Compare the checksum of the
# tarball with the one listed on https://go.dev/dl/ before you unpack it.
curl -fsSLO https://go.dev/dl/go1.27.2.linux-amd64.tar.gz
sha256sum go1.27.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.27.2.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH

git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git && cd TBP-NETWORK
scripts/devtest/site.sh m1 init --address <M1> --env "<provider, size, region>"
scripts/devtest/site.sh m1 up
scp ~/tbp-site-m1/packs/m2.pack.tgz <user>@<M2>:      # public material and binaries: no governance key in it
scp ~/tbp-site-m1/packs/m3.pack.tgz <user>@<M3>:      # the agents' private keys: M3 only
```

`init` asks for `sudo` once, to write `/etc/tbp/DEV_ENVIRONMENT`: M1 uses a seed-file issuer key instead of an HSM,
the one development switch in use, and `brokerd` refuses it without that sentinel. It raises a high-priority alarm at
every start; that is expected. M2 and M3 need no sentinel.

**On M2** — the application server:

```bash
sudo apt-get update && sudo apt-get install -y git curl jq openssl python3 ca-certificates
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git && cd TBP-NETWORK
scripts/devtest/site.sh m2 init --pack ~/m2.pack.tgz --listen <M2>:9000 --env "<provider, size, region>"
scripts/devtest/site.sh m2 up
```

`up` ends with `pepd's posture: monitor`: on its first start `pepd` records every verdict and blocks nothing.

**On M3** — the agent:

```bash
sudo apt-get update && sudo apt-get install -y git curl jq perl ca-certificates
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git && cd TBP-NETWORK
scripts/devtest/site.sh m3 init --pack ~/m3.pack.tgz --app http://<M2>:9000 --env "<provider, size, region>"
scripts/devtest/site.sh m3 check
```

`check` must end with `site M3: the plumbing works`: M3 reaches the cell over mutual TLS and is refused as it
should be (no plan; another agent's certificate; no certificate at all), and reaches the application on M2, which
refuses a request that carries no token. If it does not, that is already a finding: run `report` on the three
machines and tell us ([below](#telling-us-what-you-found)).

## What to test: does it work?

Run these in order. Each step says where it runs, and what it proves when it gives the answer shown.

| # | On | Do | You should get | It proves |
|---|---|---|---|---|
| 1 | M3 | `site.sh m3 act agent-i read doc-1` | `plan-binding-required`, no token | the cell admits nothing that no operator approved |
| 2 | M1 | `site.sh m1 sign agent-i read doc-1`, then type `sign` | the plan in clear, its hash recomputed by the tool itself, then a plan approved and the exact `m3 act …` line to run | the operators' side as a person does it: you see what you sign, and the hash you sign is the one you computed (`--yes` skips the questions, never the recomputation) |
| 3 | M3 | paste that line | `{"allow":true,"reason":"ok"}`, then on M2 `{"executed": "read doc-1", "verdict": { … "mode": "monitor", "forwarded": true }}` `[200]` | **the whole path**: enrolment by certificate, the decision, the signed token, `pepd` on another machine checking it, the application acting |
| 4 | M3 | `site.sh m3 call` (the same token again) | `[200]` but `"reason": "replay"` | in monitor, `pepd` records the would-be refusal and blocks nothing |
| 5 | M1, M3 | get a fresh token (2–3), then `site.sh m3 call read doc-9`; get another, then `site.sh m3 call --forge` | `scope-mismatch`, then `bad-signature`, both still `[200]` in monitor | scope and signature are checked by `pepd` |
| 6 | M1 | `site.sh m1 mode-proof closed` | a proof file, signed by **one** controller | closing restricts, so one controller may |
| 7 | M2 | copy that file over, `site.sh m2 mode closed --proof <file>` | `{"mode":"closed"}` | the posture is governed by the controllers, from M1, not by M2 |
| 8 | M1, M3 | repeat 4 and 5 (a fresh token each time) | now `[403]` for the replay, the other resource and the forged token; step 3 still `[200]` | closed: `pepd`'s verdict is applied |
| 9 | M1, M2 | `m1 mode-proof monitor --controllers 1` → `m2 mode monitor --proof` | `[403]` | reopening widens, so one controller is not enough |
| 10 | M1, M2 | `m1 mode-proof monitor` (two controllers) → `m2 mode monitor --proof` | `{"mode":"monitor"}` | two controllers reopen |
| 11 | M1, M3 | `m1 sign agent-w read doc-1` (answer `sign` to the operators, then to the controllers), run the line; then run it again **without** `--proof …` | `executed`; then `quorum-required` | class W needs two operators **and** two controllers |
| 12 | M3 | `site.sh m3 act agent-i read doc-1 --as agent-w`; `… --no-cert` | `agent-transport-unbound`; a TLS handshake refusal | an agent cannot use another agent's certificate, nor none |
| 13 | M2 | `site.sh m2 down`, `site.sh m2 up`, then step 3 | `pepd's posture: refused`, then `[403]` with `"forwarded": false` | a restart never silently reopens |
| 14 | M1, M2 | `m1 mode-proof monitor` → `m2 mode monitor --proof`, then step 3 | `[200]` again | two controllers reconfirm the posture |

**Read `forwarded`, not `allow`.** The application on M2 acts when `pepd` says `forwarded: true`, and that is what it
must do: in *refused* the verdict can carry `"allow": true` and `"forwarded": false` at once (the token is valid,
the posture blocks), and in *monitor* a denied request is forwarded anyway. A real application follows `forwarded`.

The proofs live a few minutes (about four): do steps 6–7, 9 and 10, and 14 without a long pause between the machines.

## Attack it

**From M3 — the network position.** M3 is the one machine an adversary is most likely to hold. Try, and expect:

| Try | Expected |
|---|---|
| `scripts/devtest/site.sh m3 act … --no-cert` | the handshake is refused: no HTTP answer |
| `curl -i -X POST -d '{}' http://<M1>:8443/v1/actions` (plain HTTP, no TLS) | `400 Client sent an HTTP request to an HTTPS server`: never a decision, the cell has no plaintext listener |
| `curl http://<M2>:8443/v1/evaluate` (pepd's own port) | connection refused: `pepd` listens on M2's loopback only |
| scan M1 and M2 (`nmap -p- <M1> <M2>`) | only the ports you opened: 22 and 8443 on M1, 22 and 9000 on M2 — nothing else that TBP started |
| `site.sh m3 act agent-i … --as agent-w` | `agent-transport-unbound` |
| a request with a forged, replayed or foreign-scope token | `bad-signature`, `replay`, `scope-mismatch`: `[403]` once closed |
| a request to the application with a missing, empty or giant token | refused before or by `pepd`, never executed |

**On M2 — someone who can write the server's files.** Run `site.sh m2 down` first, and restore the file after.

| Try | Expected on `m2 up` |
|---|---|
| add a second key to `~/tbp-site-m2/issuer-keyring.json` (trust another issuer) | `pepd` refuses to start: `provisioning-divergence` |
| `sed -i 's/^TBP_QUORUM_MIN=2$/TBP_QUORUM_MIN=1/' ~/tbp-site-m2/m2.env` | `pepd` refuses to start, naming `quorum-settings` |
| `echo changed >> ~/tbp-site-m2/app/ai-container.txt` (a measured file) | `pepd` refuses to start: `manifest-boot-divergence` |
| alter one byte of `~/tbp-site-m2/opa/bundle.tar.gz` | OPA does not start: `load error: bundle …` |

**On M1 — the cell's own files**, and the operators' and agents' sides of the cell: the attempts of
[solo.md](solo.md) ("What you can attack, from three positions") apply to M1 unchanged, with `site.sh m1` for the
paths and variables; lowering `TBP_QUORUM_MIN` in `~/tbp-site-m1/m1.env` stops `brokerd`, naming `quorum-settings`.

Anything you can do that the system **accepts silently** is the kind of finding we want most. Known limits are in the
[README](../../README.md) ("Honesty about where this stands"), in [CHANGELOG.md](../../CHANGELOG.md) and in
[governed-acts.md](../governed-acts.md).

## Telling us what you found

We want your numbers and your comments — including "I got stuck here" — **for each environment you try**.

**Your numbers.** On each machine run `scripts/devtest/site.sh m1 report` (or `m2`, `m3`) and paste the three
reports. A report records the commit, the system (OS, kernel, CPUs, memory), the environment label you gave, the
versions, how long `init` and `up` took, and:

- **M1** the cell's counters;
- **M2** `pepd`'s posture and counters, and the application → `pepd` verdict latency (a malformed token, the
  cheapest verdict);
- **M3** the decision round trip to the cell over mutual TLS (a new connection each time, so it includes the TLS
  handshake and **your network**) and the round trip to the application.

No report contains a key, a seed, a path, an address or a host name.

About latency: a decision's leaf is written into the signed log before the cell answers (no leaf, no answer), so on
our runs a decision takes about half a second, most of it, as far as we can tell, that write; we have not separated
it out. What your network adds is the difference you will see on M3. These are measures of this setup in your
environment, not performance claims: if yours differ a lot, that is useful to know.

**Your comments**, in the way that fits:

| What | Where |
|---|---|
| A step that did not work, a doc that is wrong, a behaviour that differs from what is written, your timings, a suggestion | a public GitHub issue, with the **Dev-test feedback** template (title starts with `[dev-test]`), the three reports pasted |
| Anything exploitable: a way past a refusal, a silent acceptance, a leaked secret | **privately**, as [SECURITY.md](../../SECURITY.md) says — not a public issue |

What makes a report useful: what you tried (the exact command), what you expected, what happened, and the reports.

## What this does not tell you

- **Key custody and separation between people.** Every governance key — the controllers', the operators', the CAs' —
  sits in one directory on M1, under one user. A compromise of that user is a compromise of the cell. A real site
  prevents that with separate people and HSMs.
- **The issuer key is a seed file**, which is why M1 declares the development sentinel.
- **The certificates live 30 days**, issued by two CAs on M1 (one for the cell's own certificate, one dedicated to the
  agents').
- **M2's measured boot uses two stand-ins** — the `pepd` binary where a broker binary would be, a placeholder file
  where an AI container would be — and records its reference at the first start. A real server measures the real ones.
- **There is no console.** Everything is done on a command line: `m1 sign` shows you a plan and asks you to type
  `sign`; `m1 mode-proof` signs the controllers' proofs; `m1 status` and `report` show counters; the audit trail is read
  with `tbp-audit verify`. There is no dashboard and no screen. `supervisord` (read-only JSON over a Unix socket,
  [superviseur.md](../superviseur.md)) exists in this repository but is not part of this test, and nothing in the
  repository lets an operator *sign* from anything but the command line. What a console should show and let people
  do, and in what form, is an open question ([#329](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/329)): tell us what you missed.
- **One of each.** One cell, one server, one agent host. No supervisor, no multi-cell, no 802.1X NAC, and the
  network isolation of [network-isolation.md](../network-isolation.md) is not set up: you bring the firewall.
- **The application is a stand-in** (`scripts/devtest/site-app.py`, Python standard library), not a real service.

## Commands

| `site.sh` | Does |
|---|---|
| `m1 init --address <M1> [--listen addr:port] [--env label]` | builds the binaries, makes the keys, the signed rules, the two CAs and the agents' certificates, the environment and the two packs |
| `m1 up` / `down` / `status` | starts OPA and `brokerd` / stops them / shows them and the counters |
| `m1 sign <agent> <action> <resource> [--yes]` | the operators' (and for class W the controllers') side of one action: submits the plan, shows it in clear, recomputes its hash, asks you to type `sign`; prints the `m3 act` line to run |
| `m1 grant <agent> <action> <resource>` | the same as `sign --yes` (no questions; the hash is still recomputed) |
| `m1 mode-proof closed\|monitor [--controllers N]` | the controllers' proof for M2's `pepd`: one controller to close, two to reopen |
| `m1 pack` | rewrites the two packs |
| `m2 init --pack <m2.pack.tgz> --listen <M2>:9000 [--env label]` | unpacks, writes `pepd`'s environment (a real measured boot, no development switch) |
| `m2 up` / `down` / `status` | starts OPA, `pepd` and the application / stops them / shows them |
| `m2 mode closed\|monitor --proof <file>` | posts the controllers' proof to `pepd` |
| `m3 init --pack <m3.pack.tgz> --app http://<M2>:9000 [--env label]` | installs the agents' certificates |
| `m3 check` | the plumbing: reaches the cell and the application, refused as it should be |
| `m3 act <agent> <action> <resource> [--binding HEX] [--proof HEX] [--as agent] [--no-cert]` | asks the cell, then presents the token to M2 |
| `m3 call [<action> <resource>] [--forge]` | presents the last token again, for another resource, or with a byte flipped |
| `<role> report` · `<role> listeners` · `<role> reset` | the report to paste · what the machine listens on · stops and deletes everything it made (M1 removes the sentinel if it made it) |

`init` refuses a machine that already holds `/var/lib/tbp`, or `/etc/tbp/brokerd.env`, `/etc/tbp/pepd.env` or
`/etc/tbp/quorum-keyring.json` (it looks like a real deployment), refuses root unless `DEVTEST_ALLOW_ROOT=1`
(throw-away containers), and a `TBP_SITE_HOME` too long for Unix socket paths. Each machine's files live in
`$TBP_SITE_HOME` (default `~/tbp-site-m1`, `~/tbp-site-m2`, `~/tbp-site-m3`). When you are done, `reset` on each
machine, or destroy the machines.
