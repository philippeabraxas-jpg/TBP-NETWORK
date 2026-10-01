# deploy/scale-1.md — scale 1: one machine, the administrator alone (issue #86)

_Version française : [scale-1.fr.md](scale-1.fr.md)._

Scale 1 is one machine, one cell, one administrator: `pepd` + a local OPA +
one registry. No `brokerd`, no supervisor, no fencing. It is the same TBP as
every other scale with a **different setting of the security bricks** —
[scales.md](scales.md) lists which ones and why. The quorum is the one that
matters here: `k = 1`, so **the administrator alone signs** every governed act
(posture switch, provisioning transition, measured-boot transition).

`k = 1` does not mean "no signature": an act without a valid signature from a
key pinned in the quorum keyring is refused exactly as at any other scale.

> The `scale1` phase of `deploy/selftest/` runs this guide's sequence against
> the real binaries (`go run ./deploy/selftest -phase scale1`). If a command
> below diverges from the selftest, the selftest breaks: fix the guide or the
> code, never both behind each other's back.

Not covered at this scale, on purpose: multi-cell fencing and epoch lease
(#197), inter-cell transport (#187), the mTLS network listener (#124). Moving
to scale 2 or above means changing settings, not reinstalling: see
[scales.md](scales.md).

#### Step 1 — Base: machine, binaries, OPA

**Verifiable prerequisite**: a Debian machine you administer alone, `go`
(the version pinned by `go.mod`) and `opa` in the `PATH`.

**Command**: follow [cellule.md](cellule.md) **steps 1 to 5** unchanged
(machine, build of `pepd`, restricted OPA capabilities, signed bundle, OPA on
its Unix socket). Nothing in those steps depends on the scale.

**Observable success criterion**: `curl -s --unix-socket /run/tbp/opa.sock
http://localhost/health` answers 200 and the bundle is loaded with its
signature verified (cellule.md step 5).

**On failure: STOP** — do not start `pepd` against an OPA that has not
verified the bundle signature.

#### Step 2 — Create the administrator key and the quorum keyring (k = 1)

**Verifiable prerequisite**: step 1 green; a directory `/etc/tbp` at 0700
owned by the service account; a place **off this machine** to keep a copy of
the administrator key (a sealed envelope, a password manager, an offline
disk).

**Command**:

```bash
go build -o /usr/local/bin/quorumproof ./src/pep/cmd/quorumproof
quorumproof keygen -key /etc/tbp/admin.key -keyring /etc/tbp/quorum-keyring.json
```

**Observable success criterion**: the command prints one `kid=` and one
`public=`; `/etc/tbp/quorum-keyring.json` holds **exactly one** entry
(`{"<kid>": "<public key>"}`); `/etc/tbp/admin.key` is 0600. Running the
command a second time with the same `-key` fails (an existing key is never
overwritten).

**On failure: STOP** — a keyring with more than one entry is not scale 1, and
an empty one blocks every switch. The key is software: it is the price of
scale 1 (a lost or stolen key: the old quorum can no longer authorise its
own replacement — it is a re-engagement of the cell's trust, see [recovery.md](recovery.md) B). Store the off-machine copy **now**; `pepd` reminds you at every start.

#### Step 3 — Start pepd with the scale-1 settings

**Verifiable prerequisite**: steps 1 and 2 green; the issuer keyring, the cell
salt and `TBP_POLICY_ID` prepared as in cellule.md step 6.

**Command**: write `/etc/tbp/pepd.env` as in [cellule.md](cellule.md) step 6,
with these values (adapt the paths to the machine):

```bash
#   TBP_TOPOLOGY=mono                # single cell, explicit (#128) — and NO
#                                    # TBP_CELL_BROKER_SOCKET
#   TBP_QUORUM_MIN=1                 # the administrator alone
#   TBP_QUORUM_KEYRING_FILE=/etc/tbp/quorum-keyring.json
#   TBP_PROVISIONING_WITNESS_FILE=/var/lib/tbp/pepd-provisioning-witness.json
#   TBP_MEASURED_BOOT_MANIFEST_FILE=/var/lib/tbp/cell-a-measured-boot.json
set -a; . /etc/tbp/pepd.env; set +a
/usr/local/bin/pepd &
curl -s --unix-socket /run/tbp/pepd-admin.sock http://localhost/v1/mode
```

**Observable success criterion**: `GET /v1/mode` returns
`{"mode":"monitor"}` (first start only, §5.3); `pepd` refuses to start if
`TBP_TOPOLOGY` is missing or if a broker socket is set with `mono`.

**On failure: STOP** — do not "fix" a refusal by setting any
`*_DEV_UNSAFE` flag: those are dev/lab only and refused in production by the
`DEV_ENVIRONMENT` sentinel (#113).

#### Step 4 — Prove that the administrator alone is the quorum

**Verifiable prerequisite**: step 3 green, mode `monitor`.

**Command**:

```bash
# 1. no signature: refused
curl -s -o /dev/null -w '%{http_code}\n' --unix-socket /run/tbp/pepd-admin.sock \
  -X POST -d '{"mode":"closed","signatures":[]}' http://localhost/v1/mode
# 2. the administrator signs the "mode-closed" act for THIS cell
quorumproof sign -condition mode-closed -cell cell-a -key /etc/tbp/admin.key -out /tmp/proof.json
jq '. + {mode:"closed"}' /tmp/proof.json | curl -s -o /dev/null -w '%{http_code}\n' \
  --unix-socket /run/tbp/pepd-admin.sock -X POST -d @- http://localhost/v1/mode
shred -u /tmp/proof.json
```

**Observable success criterion**: the first call prints `403`, the second
`200`, and `GET /v1/mode` then returns `{"mode":"closed"}`. The proof is bound
to the condition and the cell: the same file does not open any other act or
any other cell.

**On failure: STOP** — a `200` on the first call means the quorum is not
enforced; do not go further and do not enable closed mode elsewhere.

#### Step 5 — Restart drill: refused until the administrator reconfirms

**Verifiable prerequisite**: step 4 green, mode `closed`.

**Command**: kill `pepd`, restart it with the same environment, then read
`GET /v1/mode`; reconfirm with `quorumproof sign -condition mode-monitor …`
and the same `POST` shape as step 4.

**Observable success criterion**: after the restart the mode is `refused` (not
`monitor`) and every evaluation is denied; after the administrator's
signature the mode is the one that was signed.

**On failure: STOP** — a restart that comes back in `monitor` or `closed`
without a signature is the regression of security review #93.
