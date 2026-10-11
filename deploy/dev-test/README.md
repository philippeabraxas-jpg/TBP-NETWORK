# deploy/dev-test — the decision plane of a scale-2 cell: run it, attack it, tell us what happened

_Version française : [README.fr.md](README.fr.md)._

> **Not for production.** Every key this makes is thrown away and lives on the same machine. It proves nothing
> about key custody, about separation between real people, or about a genesis ceremony. Use it on a virtual
> machine you can lose, with no real data and no real agent behind it.

One command sets up the **decision plane** of a scale-2 cell — `brokerd` and its OPA, the same chain
[scale-2.md](../scale-2.md) builds by hand — so that you can run it, try to break it, and report what you find,
without spending an afternoon on key ceremonies first. The point is to test **the real thing**: the same binaries, the same code paths, the same
refusals. The more people try to break it now, the fewer gaps a production release will carry.

## What this tests, and what it does not yet

A scale-2 site is **several machines** behind one `brokerd`: application servers each running a `pepd`, agents on
their own machines, enrolled in the cell. This first stage runs only the cell's decision plane, on one machine.
Read the table before you decide what to attack.

| Part of a scale-2 cell | Tested here |
|---|---|
| Admission by the cell: agent registry, class resolved by the cell, strict requests | **yes** |
| Rules: a signed bundle on OPA, restricted capabilities | **yes** |
| Plans: signed submission, role split, `k` approvals, submitter ≠ approver | **yes** |
| Quorum for class W: `k = 2` of 3 controllers, single-use proofs | **yes** |
| Tokens: issued and signed by `brokerd` | **yes — but nothing checks them yet** |
| Tokens at the enforcement point: validation, expiry, replay, object seal, quota (`pepd`) | **no** — stage 2 |
| Provisioning witness and the fail-closed start | **yes** |
| Machines enrolled and bound to a certificate, the mTLS listener, an agent on another machine | **no** — stage 3 |
| Network isolation between agents and the outside | **no** — stage 3 |
| Supervisor, multi-cell | **no** |

The stages, each a deployment you can run and attack:

1. **This one.** The decision plane on one machine.
2. **Next: `pepd` on the same machine, as an application server.** A token issued by `brokerd` is presented to
   `pepd`, which checks it: forged, expired, replayed, wrong object, over quota. This tests the token path end to
   end. No second machine yet.
3. **After: three machines** on one private network — the cell, a server running `pepd`, an agent — with the agent
   enrolled in the registry and bound to its certificate, the mTLS listener with an agent CA, and the
   network-isolation check (step 7 of [scale-2.md](../scale-2.md)). This is the real scale-2 test.

Until stage 2 exists, a token that `brokerd` issues is never presented to anyone: a flaw in how it is checked cannot
be found with this setup. We say so rather than let a green `demo` suggest otherwise.

## In ten minutes

You need one Debian 12 virtual machine (see "What machine do you need" below) and a user with `sudo`. The commands
below are the whole procedure; the first run prints `demo passed` at the end. We have not yet timed a cold start on
a fresh Debian 12 — your timing is part of what we ask for.

```bash
# 1. Tools: git, curl, jq, openssl
sudo apt-get update && sudo apt-get install -y git curl jq openssl ca-certificates

# 2. OPA, the version CI uses, checked against its published checksum
curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.20.2/opa_linux_amd64_static
curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.20.2/opa_linux_amd64_static.sha256
sha256sum -c opa_linux_amd64_static.sha256          # must say: opa_linux_amd64_static: OK
sudo install -m 0755 opa_linux_amd64_static /usr/local/bin/opa

# 3. Go, at least the version in go.mod (Debian 12's own package is 1.19, too old). Compare the checksum
#    of the tarball with the one listed on https://go.dev/dl/ before you unpack it.
curl -fsSLO https://go.dev/dl/go1.27.2.linux-amd64.tar.gz
sha256sum go1.27.2.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.27.2.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH

# 4. The repository, and the cell
git clone https://github.com/philippeabraxas-jpg/TBP-NETWORK.git && cd TBP-NETWORK
scripts/devtest/devtest.sh init      # builds three binaries, makes keys, signs the rules (~10 s once Go is warm)
scripts/devtest/devtest.sh up        # OPA, then brokerd
scripts/devtest/devtest.sh demo      # 12 checks: what is refused, what is allowed, and why
```

`init` asks for `sudo` once, to write `/etc/tbp/DEV_ENVIRONMENT` (explained below). When a published DEV-TEST
release carries the binaries, steps 3 and the build disappear: you will only need OPA and the release files.

If `demo` does not end with `demo passed`, that is already a finding: run `scripts/devtest/devtest.sh report`
and tell us ([below](#telling-us-what-you-found)).

## What machine do you need

**One, at this stage** (stages 2 and 3 above add `pepd` and then more machines). Here the cell, the agent, the operators, the controllers and the attacker are all roles you
play on the same virtual machine, talking over Unix sockets in a directory only your user can open. Nothing
listens on TCP, so there is no port to open, no second machine to attack from, and no cloud service to depend on.

| Role | Where it runs | How you play it |
|---|---|---|
| The cell | the VM | `devtest.sh up` starts OPA and `brokerd` |
| An agent | the VM | `curl` on the **agent socket** (`POST /v1/actions`) |
| Operators and controllers | the VM | `quorumproof` with the key files `init` made |
| The attacker | the VM, as the same user | you, from one of the three positions below |

Where to put the VM: any cloud virtual machine (a small droplet or instance is fine) or a local one (KVM,
VirtualBox, multipass). Not on a laptop or a server that holds anything you care about, and not on a network you
cannot afford to expose: the cell does not open a port, but the machine is still yours to protect. We have not
measured the smallest machine that works; our runs used 4 CPUs and 16 GB. `report` records what you
used, so please tell us.

What this does **not** let you test is the network: an agent on another machine, the mTLS listener, the network
isolation between agents and the outside (step 7 of [scale-2.md](../scale-2.md)). Those need a second machine and
are not set up here.

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
agents, and anything multi-cell. What it **cannot** tell you: whether your key custody, your ceremony or your
network isolation are sound — because the controllers, the operators and the cell all sit under one user on one
machine, a compromise of that user is a compromise of every key. That is what a real deployment prevents with
separate people and HSMs.

## What you can attack, from three positions

After `init` and `up`, load the variables once and define one helper:

```bash
eval "$(scripts/devtest/devtest.sh env)"
post() { curl -sS --unix-socket "$1" -X POST "${@:3}" -w ' [%{http_code}]\n' "http://localhost$2"; }
```

Each attempt below was run against a running deployment and gave the answer shown; **the expected answer is what you
should get.** A different answer is a finding.

### Position 1 — an agent (it can only reach the agent socket)

| Try | Command | Expected |
|---|---|---|
| Two subjects in one request | `post $DT_AGENT_SOCK /v1/actions -d '{"subject":"agent-i","subject":"agent-w","intent":"{}"}'` | `request-invalid`, `duplicate-key`, `[400]` |
| A field the contract does not have | `post $DT_AGENT_SOCK /v1/actions -d '{"subject":"agent-i","intent":"{}","class":2}'` | `request-invalid`, `unknown-field`, lists the accepted ones, `[400]` |
| Claim a lower class for a class-W agent | `post $DT_AGENT_SOCK /v1/actions -d '{"subject":"agent-w","intent":"{\"action\":\"read\",\"resource\":\"doc-1\",\"class\":1}"}'` | `quorum-required`: the class comes from the cell's registry, not from the agent |
| A body over 64 KiB | `head -c 70000 /dev/zero \| tr '\0' a > /tmp/big; post $DT_AGENT_SOCK /v1/actions --data-binary @/tmp/big` | `request-invalid`, `body-unreadable`, `[400]` |

### Position 2 — an operator (it holds operator keys and reaches the admin socket)

First make a plan to work on, signed by the key that may submit, and keep its hash:

```bash
echo '{"subject":"agent-i","steps":[{"action":"read","resource":"doc-9","params_hex":""}]}' > /tmp/plan.json
quorumproof plansubmit -cell $DT_CELL -plan /tmp/plan.json -key $DT_KEYS/operator-4.key -out /tmp/s4.json
H=$(curl -sS --unix-socket $DT_ADMIN_SOCK -X POST -d @/tmp/s4.json http://localhost/v1/supervision/plan/submit | jq -r .plan_hash)
```

| Try | Command | Expected |
|---|---|---|
| Submit a plan without a signature | `post $DT_ADMIN_SOCK /v1/supervision/plan/submit -d @/tmp/plan.json` | refused: the cell wants to know who submits, `[400]` |
| Submit with a key that cannot submit | `quorumproof plansubmit -cell $DT_CELL -plan /tmp/plan.json -key $DT_KEYS/operator-1.key -out /tmp/s.json && post $DT_ADMIN_SOCK /v1/supervision/plan/submit -d @/tmp/s.json` | refused: the key does not hold the submission role, `[400]` |
| Submit a plan signed for another cell | `quorumproof plansubmit -cell cell-other -plan /tmp/plan.json -key $DT_KEYS/operator-4.key -out /tmp/s.json && post $DT_ADMIN_SOCK /v1/supervision/plan/submit -d @/tmp/s.json` | refused: invalid signature for the pinned keyring, `[400]` |
| Approve a plan with the key that submitted it | `quorumproof planapprove -plan-hash $H -expires-at $(date -u -d '+30 minutes' +%Y-%m-%dT%H:%M:%SZ) -key $DT_KEYS/operator-4.key -out /tmp/a.json && post $DT_ADMIN_SOCK /v1/supervision/plan/approve -d @/tmp/a.json` | refused: the key does not hold the approval role, `[400]` |
| Revoke with an approver's key | `quorumproof planrevoke -plan-hash $H -key $DT_KEYS/operator-1.key -out /tmp/r.json && post $DT_ADMIN_SOCK /v1/supervision/plan/revoke -d @/tmp/r.json` | refused: the key does not hold the revocation role, `[400]` |
| Check the broker's hash before signing | `quorumproof planhash -cell $DT_CELL -policy-id $DT_POLICY_ID -submitted-at 2026-01-01T00:00:00Z -plan /tmp/plan.json -expect $(printf 'a%.0s' $(seq 1 64))` | `plan_hash DIFFÉRENT … ne signez pas`, exit code 1 |

The full flow that **is** allowed — a class-I plan, a class-W action with two operators and two controllers — is
`devtest.sh demo`; read it as the specification of what should pass.

### Position 3 — someone who can write the cell's files

These stop the cell from starting; each leaves a clear reason. Run `devtest.sh down` first, and restore the file
after (keep a copy).

| Try | Command | Expected |
|---|---|---|
| Add an agent to the registry by hand | `cp $DT_HOME/agents.json /tmp/agents.bak; jq '. + {"agent-evil":{"class":3}}' /tmp/agents.bak > $DT_HOME/agents.json; scripts/devtest/devtest.sh up` | `brokerd` refuses to start, names `agent-registry` and prints the condition a quorum would have to sign |
| Lower the quorum | `sed -i 's/^TBP_QUORUM_MIN=2$/TBP_QUORUM_MIN=1/' $DT_HOME/brokerd.env; scripts/devtest/devtest.sh up` | `brokerd` refuses to start, naming `quorum-settings` |
| Alter one byte of the signed rules | edit `$DT_HOME/opa/bundle.tar.gz` | OPA does not start: `load error: bundle …`, a `digest mismatch` or a corrupt archive depending on where you hit |
| Trust another signer | replace `$DT_HOME/opa/policy-verify.pub` with another public key | OPA does not start: `failed to verify JWT signature` |

Restore the originals, then `devtest.sh up` and `devtest.sh demo` must pass again. Anything you can do from this
position that the cell **accepts silently** is the kind of finding we want most.

Beyond this list, [scale-2.md](../scale-2.md), [governed-acts.md](../governed-acts.md) and
[integration-contract.md](../integration-contract.md) say what each part promises: a promise you can break is a
finding. Known limits are written in the [README](../../README.md) ("Honesty about where this stands"), in
[CHANGELOG.md](../../CHANGELOG.md) and in [governed-acts.md](../governed-acts.md).

## Telling us what you found

We want your numbers and your comments, including "I got stuck here".

**Your numbers.** Run `scripts/devtest/devtest.sh report` and paste what it prints. It records the commit, the
system (OS, kernel, CPUs, memory), the OPA and Go versions, how long `init` and `up` took, the result of the last
`demo`, the broker's counters, and the latency of the cheapest decision (an agent with no plan, refused, 50
requests over the Unix socket). It contains **no** key, seed, path, host name or address.

About that latency: as far as we can tell, most of it is the time to write the decision's leaf into the signed log
before the broker answers (no leaf, no answer); we have not separated it out. On our run (4 CPUs, 16 GB, Ubuntu
24.04) a refusal took about half a second. That is a measure of this setup on your machine, not a performance
claim; if yours is very different, that is useful to know.

**Your comments**, in the way that fits what you found:

| What | Where |
|---|---|
| A step that did not work, a doc that is wrong, a behaviour that differs from what is written, your timings, a suggestion | a public GitHub issue, using the **Dev-test feedback** template (title starts with `[dev-test]`) |
| Anything exploitable: a way past a refusal, a silent acceptance, a leaked secret | **privately**, as [SECURITY.md](../../SECURITY.md) says — not a public issue |

What makes a report useful: what you tried (the exact command), what you expected, what happened, and the
`report` output. A failing command is the best reproduction.

## Commands

| Command | What it does |
|---|---|
| `devtest.sh init` | builds or copies the binaries, makes the keys, the signed bundle and the environment — once |
| `devtest.sh up` / `down` | starts OPA and `brokerd` in the background / stops them |
| `devtest.sh demo` | 12 checks; fails, showing the unexpected answer, if the cell behaves differently |
| `devtest.sh env` | prints the variables used above (`DT_AGENT_SOCK`, `DT_ADMIN_SOCK`, `DT_KEYS`, `DT_CELL`, `DT_POLICY_ID`, …) |
| `devtest.sh status` | is it running; the broker's counters |
| `devtest.sh report` | a report with no secret in it, to paste into an issue |
| `devtest.sh reset` | stops, deletes everything this made, removes `/etc/tbp/DEV_ENVIRONMENT` if it made it |

`init` refuses a machine that already holds `/var/lib/tbp`, or `/etc/tbp/brokerd.env`, `/etc/tbp/pepd.env` or
`/etc/tbp/quorum-keyring.json` (it looks like a real deployment), refuses root unless `DEVTEST_ALLOW_ROOT=1`
(throw-away containers), and refuses a `TBP_DEVTEST_HOME` too long for Unix socket paths. Everything lives in
`$TBP_DEVTEST_HOME` (default `~/tbp-devtest`):

| Path | What |
|---|---|
| `keys/controller-1..3.key` | the three controllers: any two sign a class-W action (`k = 2` of 3) |
| `keys/operator-1..4.key` | `operator-1`, `operator-2`: approve plans · `operator-3`: `revoke` and `arbitrate` only · `operator-4`: submits plans |
| `genesis/manifest.json`, `keys/quorum-keyring.json` | the public keys of the controllers |
| `opa/` | restricted capabilities, signing key, verification key, signed bundle, the OPA launch arguments |
| `brokerd.env`, `operators.json`, `agents.json` | the cell's settings; `agents.json` has `agent-f` (class F), `agent-i` (class I), `agent-w` (class W) |
| `run/` | the Unix sockets: `broker.sock` (agents) and `broker-admin.sock` (operators) |
| `registry/`, `audit/` | the cell's log and the encrypted journal of cleartexts ([audit.md](../audit.md)) |
| `log/` | `opa.log`, `brokerd.log` — expect one high-priority alarm at start: a development environment is declared |
