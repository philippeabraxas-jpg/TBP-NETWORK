# deploy/scale-2.md — scale 2: a small site behind one `brokerd` (issue #86)

_Version française : [scale-2.fr.md](scale-2.fr.md)._

Scale 2 is a small team or site: a few machines (application servers, agents) behind **one** `brokerd`,
a single registry, a single administrator — plus a **real quorum**: `k = 2` of `n = 3` controllers, so
that no single key signs a governed act and the loss of one key does not close the cell
([recovery.md](recovery.md)). It is the same TBP as every other scale with a different setting of the
security bricks: [scales.md](scales.md) lists them, and this guide is the "scale 2" column made
executable.

What scale 2 adds to [scale-1.md](scale-1.md):

| | Scale 1 | Scale 2 |
|---|---|---|
| Quorum | `k = 1`, one key, `n = 1` | `k = 2` of `n = 3` — one spare |
| `brokerd` | absent | present: identity, class and quota resolved by the cell, never by the agent |
| Class W | n/a | needs a plan **and** 2 controllers |
| Agents | local | local, or remote over mTLS ([cellule.md](cellule.md), #124) |
| Topology | `mono` | `mono` (this guide) — `multi` is scale 3 |
| Supervisor | absent | optional ([superviseur.md](superviseur.md)) |

> The `scale2` phase of `deploy/selftest/` runs steps 1 to 6 of this guide against the real binaries
> (`go run ./deploy/selftest -phase scale2`), with the `quorumproof` commands written below. If a command
> diverges from the selftest, the selftest breaks: fix the guide or the code, never both behind each
> other's back. Step 7 (remote agents over mTLS, the application servers' `pepd`) is **not** executed by
> that phase — see its note.

#### Step 1 — Base: machine, binaries, OPA

**Verifiable prerequisite**: a Debian machine for the cell, `go` (the version pinned by `go.mod`) and
`opa` in the `PATH`.

**Command**: follow [cellule.md](cellule.md) **steps 1 to 5** (machine, restricted OPA capabilities, signed
bundle, OPA on its Unix socket), then build the two binaries this guide uses:

```bash
go build -o /usr/local/bin/brokerd ./src/broker/cmd/brokerd
go build -o /usr/local/bin/quorumproof ./src/pep/cmd/quorumproof
```

**Observable success criterion**: `curl -s --unix-socket /run/tbp/opa.sock http://localhost/health`
answers 200 with the bundle's signature verified; both binaries are in place.

**On failure: STOP** — do not start `brokerd` against an OPA that has not verified the bundle signature.

#### Step 2 — Three controllers, `k = 2`

**Verifiable prerequisite**: step 1 green; a directory `/etc/tbp/keys` at 0700; **three people or three
places** to keep the controller keys (a software key is the scale-2 floor; put them in an HSM as soon as the
site can — [cellule.md](cellule.md)).

**Command**: create the three controller keys **on the machines that will sign**, and build the genesis
manifest from their public keys, in order (the position of a key in the manifest is its `key_id`):

```bash
for i in 1 2 3; do
  quorumproof keygen -key /etc/tbp/keys/controller-$i.key -keyring /etc/tbp/quorum-keyring.json
done                       # prints  kid=…  public=<64 hex>  for each
# genesis/manifest.json: {"pubkeys": ["<public 1>", "<public 2>", "<public 3>"]}  — in this order
```

Distribute each `controller-N.key` to its own custodian; only `/etc/tbp/quorum-keyring.json` and
`manifest.json` stay on the cell (public keys).

**Observable success criterion**: three `public=` lines were printed; `quorum-keyring.json` holds three
entries; the manifest lists the same three keys. `TBP_QUORUM_MIN=2` is then **2 of 3**: any two
controllers sign, the third is the spare. Running `keygen` twice with the same `-key` fails (a key is never
overwritten).

**On failure: STOP** — a keyring with two entries for `k = 2` has no spare: losing one key closes the cell
(`brokerd` says so at start). Do not go on with `n ≤ k`.

#### Step 3 — Start `brokerd` (topology `mono`, `k = 2`)

**Verifiable prerequisite**: steps 1 and 2 green; the agent registry (`agents.json`: each agent and its
class), the operator keys (`operators.json`, the keys that approve plans), the issuer seed and the cell salt
prepared as in [cellule.md](cellule.md) step 7; `TBP_PROVISIONING_WITNESS_FILE` outside
`TBP_REGISTRY_DIR`. The **operator key** is created like a controller key — it is a different key, held by
the person who approves plans:
`quorumproof keygen -key /etc/tbp/keys/operator.key -keyring /tmp/operator-ring.json`, and its `public=` goes
into `operators.json` (`["<public>"]`).

**Command**: write `/etc/tbp/brokerd.env` as in cellule.md step 7 with these scale-2 values, then start it:

```bash
#   TBP_TOPOLOGY=mono                 # one cell: no epoch lease (#97)
#   TBP_CLUSTER_MEMBERS=cell-a        # mono: the cell is its only member (#128)
#   TBP_QUORUM_MIN=2
#   TBP_GENESIS_DIR=/etc/tbp/genesis  # holds manifest.json (the 3 controllers)
#   TBP_AGENT_REGISTRY_FILE=/etc/tbp/agents.json
#   TBP_OPERATOR_KEYS_FILE=/etc/tbp/operators.json
#   TBP_PROVISIONING_WITNESS_FILE=/var/lib/tbp/brokerd-provisioning-witness.json
set -a; . /etc/tbp/brokerd.env; set +a
/usr/local/bin/brokerd &
curl -s --unix-socket /run/tbp/broker-admin.sock http://localhost/v1/supervision/stats
```

**Observable success criterion**: the stats route answers 200 with zero counters; the log contains **no**
`AVERTISSEMENT quorum` line (`k = 2` with a spare is the healthy case); `TBP_PROVISIONING_WITNESS_FILE` was
written.

**On failure: STOP** — an `AVERTISSEMENT quorum k=1` means the environment says `TBP_QUORUM_MIN=1`: that is
scale 1, not scale 2. A refusal naming `quorum-settings` or a file means the cell's trust files changed
since the witness: see [cellule.md](cellule.md), "Provisioning files".

#### Step 4 — A class-W action needs two controllers

**Verifiable prerequisite**: step 3 green; an agent registered class W in `agents.json`; `TBP_POLICY_ID` of
the cell (the bundle hash).

**Command**: the operator submits and approves the plan, then two controllers sign a proof for **that**
action; the agent presents both:

```bash
# 1. submit the plan FOR one agent (admin socket; "subject" must be in the registry, and only that agent can run it, #235) — it answers {"plan_hash": "<hex>"}
curl -s --unix-socket /run/tbp/broker-admin.sock -X POST \
  -d '{"subject":"agent-w","steps":[{"action":"read","resource":"doc-1","params_hex":""}]}' \
  http://localhost/v1/supervision/plan/submit
# 2. the operator approves it with the operator key, then the body is posted
quorumproof planapprove -plan-hash <plan_hash> -key /etc/tbp/keys/operator.key -out /tmp/approval.json
curl -s --unix-socket /run/tbp/broker-admin.sock -X POST -d @/tmp/approval.json \
  http://localhost/v1/supervision/plan/approve
BINDING=$(quorumproof planbind -plan-hash <plan_hash>)
# 3. two controllers sign a proof bound to (action, resource, policy) — single-use (#206)
quorumproof wproof -manifest /etc/tbp/genesis/manifest.json -action read -resource doc-1 \
  -policy "$TBP_POLICY_ID" -key /etc/tbp/keys/controller-1.key -key /etc/tbp/keys/controller-3.key -out /tmp/proof.json
# 4. the agent's intent carries plan_binding and quorum_proof (both hex) — POST /v1/actions
```

**Cutting a plan approved by mistake (#244).** Do not wait for it to expire (up to 24 h): the operator revokes it,
signed like an approval — the signed message is different (`TBPR1`), so an approval signature never revokes:

```bash
quorumproof planrevoke -plan-hash <plan_hash> -key /etc/tbp/keys/operator.key -out /tmp/revocation.json
curl -s --unix-socket /run/tbp/broker-admin.sock -X POST -d @/tmp/revocation.json \
  http://localhost/v1/supervision/plan/revoke
```

The agent's next step is then refused `plan-revoked`; an unsigned or wrongly signed revocation is refused and
leaves a refusal leaf, a valid one leaves a leaf naming the operator. Works on a pending plan too.

**Observable success criterion**: the same action is **refused** with no proof (`quorum-required`) and with
one controller's proof (`quorum-insufficient`), and **allowed with a token** with two — here controllers 1 and
3, because 2 is unavailable: that is what the spare is for. The proof does not work a second time.

**On failure: STOP** — an allow with one signature means `TBP_QUORUM_MIN` is not 2; do not go on. Controllers
whose keys live in an HSM use `quorumproof wmessage` (what to sign) and `quorumproof wassemble`.

#### Step 5 — The scale is attested

**Verifiable prerequisite**: step 3 green; `brokerd` stopped.

**Command**: the scale — `TBP_QUORUM_MIN` and the topology — is part of what the provisioning witness attests
(#224). Try to lower it by editing the environment, as an attacker would:

```bash
TBP_QUORUM_MIN=1 /usr/local/bin/brokerd     # in the same environment otherwise
```

**Observable success criterion**: `brokerd` **refuses to start** and names `quorum-settings`. Even a
transition proof signed by **one** controller does not authorise it: the change is authorised only by the
quorum that was **attested** (2), not by the one you just wrote. Signed by two controllers
(`quorumproof sign -condition '<the condition the refusal prints: provisioning-transition-brokerd|from=…|to=…>' -cell cell-a -key … -key …`, then
`TBP_PROVISIONING_TRANSITION_PROOF_FILE`) it is accepted — and `brokerd` then warns at every start that
`k = 1`. Moving up a scale is the same governed act in the other direction.

**On failure: STOP** — a `brokerd` that starts with `TBP_QUORUM_MIN=1` and no proof means the witness is not
attesting the scale: do not run the cell.

#### Step 6 — Restart drill

**Verifiable prerequisite**: steps 3 to 5 green.

**Command**: kill `brokerd` and start it again with the same environment.

**Observable success criterion**: it starts (the witness matches: same files, same scale). Under the
posture rules of [cellule.md](cellule.md), a restart of `pepd` on a server comes back `refused` until a quorum
reconfirms a posture: with `k = 2`, two controllers sign (`quorumproof sign -condition mode-closed …`).

**On failure: STOP** — a restart that comes back without a quorum is the regression of security review #93.

#### Step 7 — Application servers and remote agents

**Verifiable prerequisite**: steps 1 to 6 green; the application servers prepared as in
[serveur.md](serveur.md).

**Command**: install `pepd` on each server as in [serveur.md](serveur.md) with `TBP_QUORUM_MIN=2` and the
**same** quorum keyring (`/etc/tbp/quorum-keyring.json`); for agents on other machines, turn on the mTLS
listener of `brokerd` with a dedicated agent CA ([cellule.md](cellule.md), #124) and bind each agent to its
certificate (`transport_identity` in `agents.json`) — such an agent is a **network** agent and is refused on the Unix socket (`agent-network-only`); an agent without `transport_identity` is a socket agent and is refused on the network. Give an agent used both ways two entries. Then prove that nothing leaves the agents' network except
through TBP: [network-isolation.md](network-isolation.md).

**Observable success criterion**: an agent without a certificate in the agent CA is refused at the
handshake; `deploy/verify_network_isolation.sh --mode strict` rejects every outbound probe and reaches the
proxy. Each `pepd` starts `refused` after a restart and is reconfirmed by 2 controllers.

**On failure: STOP** — do not accept agent traffic before the isolation check passes. *This step is not run
by the `scale2` selftest phase*: mTLS is covered by the tests of `brokerd` (`net_tls_test.go`) and the
application servers' `pepd` by the `mono` and `scale1` phases.

## Two keys, two places

The controllers' keys and the **keys of the cell** are different things: the cell key (`cell_log.key`,
`TBP_REGISTRY_DIR`) signs the log and stays on the machine; the controller keys sign **acts** and **never**
stay on it. Losing a controller key, losing the quorum, or a stolen key: [recovery.md](recovery.md) — rehearse
it once before you need it.

## What this scale does not cover, on purpose

- The effective profile is not yet written as a log leaf at start: it is recomputable from the witness (the
  `quorum-settings` entry is in the digest of the start leaf), but a human-readable "which profile ran on
  that day" record is tracked in #86.
- Sequence-level behavioural detection (#181) is **after** scale 2 (decision recorded in
  [scales.md](scales.md)).
- Several cells, epoch lease and fencing: scale 3 ([cellule.md](cellule.md), [superviseur.md](superviseur.md)).
