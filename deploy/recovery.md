# deploy/recovery.md — lost key, lost quorum, k = 1 (issue #199)

_Version française : [recovery.fr.md](recovery.fr.md)._

A cell that cannot be recovered is a cell that gets bypassed. Three things make that
likely if nothing is written down: a restart of `pepd` is **refused until a quorum signs a
posture again** (#93), a quorum of 1 is configurable (`TBP_QUORUM_MIN=1`), and a
governed change of a trusted file needs a proof from the controllers **as they were
attested** (#218). Lose the keys and the cell stays closed — by design. This page says
what is possible, in which order, and what is *not*.

> The Go tests named under each procedure exercise the real start-up code of `pepd` and
> `brokerd` (`setupProvisioning`, `run`). If a step below diverges from them, they break:
> fix the guide or the code, never both behind each other's back. A guide that has not
> been rehearsed is a guess: see [the drill](#the-drill) at the end.

## Which situation are you in?

Let **k** be `TBP_QUORUM_MIN` and **n** the number of pinned controller keys (entries of
`TBP_QUORUM_KEYRING_FILE` for `pepd`; entries of the genesis `manifest.json` for `brokerd`).

| Situation | Condition | Procedure |
|---|---|---|
| **A. A key is lost, the quorum survives** | at least k keys still available | [A — rotate](#a--a-key-is-lost-the-quorum-survives) |
| **B. The quorum is lost** | fewer than k keys available (scale 1: the only key) | [B — re-engage](#b--the-quorum-is-lost) |
| **C. A key is stolen, not lost** | any | [C — compromise](#c--a-key-is-stolen) first, then A or B |

Which of A or B you are in is decided by one number: **n − k** is how many keys you can
lose. At scale 1 (n = 1, k = 1) it is **zero**; a 2-of-2 has no spare either (the
start-up notice says so). Plan **n ≥ k + 1**, and keep one of the keys **sealed offline**
(an envelope in a safe, an HSM in another room): it costs nothing to the mechanism — it is
just one more pinned controller — and turns B into A.

## What a lost key had already signed

Nothing it signed is revoked, and — for a **controller** key — nothing it signed stays *usable*. An **operator** key is the exception (last bullet):

- **Quorum proofs** are bound to one condition and one cell, live 4 minutes by default, and
  (class W) are single-use even across restarts (#206). None outlives the incident.
- **Epoch tokens** already accepted stand until their own lease expires (10–300 s); a new one
  must verify under the manifest in force.
- **Past decisions** are leaves signed by the *cell* key, not by the controllers. They stay
  verifiable. Removing a controller is not retroactive.
- **Plan approvals** are the exception, and they are signed by an *operator* key (`TBP_OPERATOR_KEYS_FILE`),
  not a controller key: an approved plan stays approved until its own expiry — 1 h by default, up to 24 h.
  Since #196 a plan for a class-F or class-W agent takes k distinct operator signatures: one stolen key no
  longer approves such a plan alone (class I still takes one signature). With roles in `operators.json`
  ([scale-2.md](scale-2.md) step 3), a stolen key that only holds `revoke` cannot approve anything.
  If an operator key is lost or stolen, no console view lists *approved* plans (`/v1/supervision/arbitration`
  shows only those still pending): find them in the log — each approval leaf names the approving operator's
  key id — and cut each one with `quorumproof planrevoke` ([scale-2.md](scale-2.md), "Cutting a plan approved
  by mistake"). Before approving anything again, **recompute the plan hash from the plan in clear** with
  `quorumproof planhash` and sign only a hash you recomputed (#273): in an incident, the hash the broker
  announces is exactly what you cannot rely on.

So rotating does not rewrite history. If the key was **stolen** rather than lost, history
matters: see C.

## A — a key is lost, the quorum survives

Example: 2-of-3, one key lost, two available.

**`pepd`** (the quorum keyring)

1. Generate the replacement key (on the signer's own machine) and take its public key.
2. Edit the quorum keyring: replace the lost entry with the new one. `TBP_QUORUM_MIN` is
   unchanged.
3. Recompute the condition on **your own workstation** (#264) —
   `pepd -print-provisioning-condition -cell-vkey cell_log.vkey`, same environment file, a copy of the
   witness — and compare it with the one `pepd` prints when it refuses (`condition to sign:
   provisioning-transition-pepd|from=…|to=…`, #236): they must be identical. Have **k of the remaining
   controllers** sign the one **you** computed:
   `quorumproof sign -condition '<that condition>' -cell <cell> -key … -key … -out proof.json`
4. Set `TBP_PROVISIONING_TRANSITION_PROOF_FILE` in `pepd.env`, restart. The proof is checked
   against the keyring **as attested at the previous start**, not against the file you just
   edited — that is why the lost key's replacement cannot sign its own admission.
5. The cell comes back `refused` (#93): reconfirm the posture with k signatures from the
   **new** keyring. Then **remove** the proof line from `pepd.env`.

**`brokerd`** (the genesis manifest — `key_id` is the entry's position, 1-based)

1. **Replace the lost key in place. Never delete an entry and never reorder.** Removing an
   entry shifts every later `key_id`, and every signature already made under the old order
   stops verifying.
2. Recompute the condition on your workstation (`brokerd -print-provisioning-condition -cell-vkey cell_log.vkey`),
   compare it with the one `brokerd` prints when it refuses (`provisioning-transition-brokerd|from=…|to=…`),
   sign it with k of the remaining controllers, set
   `TBP_PROVISIONING_TRANSITION_PROOF_FILE`, restart, remove the line.
3. If the replaced entry was one of the signers of `epoch0.json` (multi-cell, `TBP_TOPOLOGY=multi`),
   `brokerd` refuses to start with `epoch0 refused`: have k controllers of the **new** manifest
   re-sign `epoch0.json` (`scripts/genesis sign` / `renew`), then restart.

`pepd` and `brokerd` hold two copies of the same set of controllers (the keyring and the
manifest): change both, in the same maintenance window.

Verified by: `TestPepdLostControllerKeyIsRotatedByTheRemainingQuorum`,
`TestBrokerdLostControllerKeyIsReplacedInPlace`,
`TestBrokerdRemovingAControllerByShiftingRanksIsRefused`,
`TestBrokerdEpoch0SignerReplacedNeedsResign` — including that, after the rotation, a proof
signed by the lost key plus one other is **refused**.

## B — the quorum is lost

Fewer than k keys are available. **By design nobody can sign anything**: no posture switch, no
provisioning transition. The cell is closed and stays so; there is no back door in the
mechanism, and no break-glass key unless you pinned one beforehand (see above).

Recovery is then not a transition authorised by the previous quorum — that quorum no longer
exists — but an **installation act by whoever administers the machine**, recorded in the log:

1. Stop `pepd` (and `brokerd`).
2. **Set the old witness aside, do not delete it**:
   `mv /var/lib/tbp/pepd-provisioning-witness.json{,.lost-$(date +%F)}` (same for `brokerd`). It is
   the evidence of what the cell trusted before.
3. Create the new controllers: at scale 1,
   `quorumproof keygen -key /etc/tbp/admin.key.new -keyring /etc/tbp/quorum-keyring.new.json`
   (a **new** keyring file: `keygen` adds to an existing one), then put the new keyring in place.
   Store the off-machine copy **now**.
4. Sign a transition with the **new** key(s): recompute the condition (`pepd -print-provisioning-condition
   -cell-vkey cell_log.vkey`; with no witness it reports `state=no-witness` and `provisioning-transition-pepd|from=000…0|to=…`
   — `from` is zero, #236) and compare it with the refusal's, then
   `quorumproof sign -condition '<that condition>' -cell <cell> -key /etc/tbp/admin.key.new -out proof.json`,
   set `TBP_PROVISIONING_TRANSITION_PROOF_FILE`, start `pepd`.
5. With no witness on a registry that has already lived, the daemon refuses without a proof
   (so a deleted witness is not an open door); with one, it **re-engages** and writes a
   `re-engaged` leaf. Reconfirm the posture with the new key, then remove the proof line.

Consequences, to state before you do it:

- **This is trust on first use.** Anyone with root on the machine and able to generate a key
  can do the same. That is not a hole this procedure opens: it is the residual limit of the
  mechanism (#218) — whoever can erase the witness and the old keyring controls the cell.
  What protects you is the **leaf**: the re-engagement is appended to the log (a manifest-kind
  leaf, hash-only: whoever holds the cell salt recomputes it to name the event), so a supervisor
  or auditor can establish that the root of trust changed, and when. Review it.
- The cell key (`cell_log.key`) is a different key and is **not** replaced here: the history
  stays continuous and verifiable.
- **Scale ≥ 2 (several cells, a supervisor): not rehearsed.** Re-engaging one cell's quorum
  while its peers hold the old epoch and the old manifest is a cluster-level operation (new
  genesis, the other cells and the supervisor told, epoch continuity). The mechanism is the same
  code; the coordination is not written yet and is tracked with #86 / #33.

Verified by: `TestPepdLostQuorumIsRecoveredByReEngagement` — including that the old key
authorises nothing afterwards, and that a proof signed only by the new key is refused while the
old witness is still there.

## C — a key is stolen

A stolen key is not a lost key: rotating it does not undo what it did.

1. **Rotate first** (A) if the quorum survives and the thief alone cannot reach k. If k = 1, the
   thief **is** the quorum: go to B at once, and treat the cell as compromised until reviewed.
2. **Read the log for the window**: posture switches, provisioning transitions and
   re-engagements (hash-only leaves: recompute them with the cell salt), class-W approvals,
   since the last moment you are sure the key was safe.
3. Re-run the measured start-up (`pepd`) and compare the provisioning witness with what you
   expect; anything unexplained is an incident, not a rotation.

## k = 1 in production

Scale 1 **is** k = 1 ([scale-1.md](scale-1.md)): the administrator alone signs, and that is a
legitimate setting, so it is not refused. What `pepd` and `brokerd` now do is say so at every
start, in the log, with the same notice for a quorum with no spare (n ≤ k):

```
pepd: AVERTISSEMENT quorum k=1 (1 contrôleur(s) épinglé(s)) : une seule clé signe tout acte gouverné …
```

Read it as a checklist: is there an off-machine copy of the key *today*? Is this still the scale
you mean to be at? Above scale 1, k ≥ 2 and n ≥ k + 1 are the recommendation
([scales.md](scales.md)). `TBP_QUORUM_MIN` is read from the environment, but since #224 the provisioning witness
attests it (the `quorum-settings` entry: k and topology): lowering it by editing the environment
diverges from the witness, and the change is authorised only by the k that was **attested**, not
by the one you just wrote.

## The drill

The procedure only exists if it has been exercised. **On a copy of the cell, never on the
production one**, at least once a year and after every change of controllers:

1. Copy the env files, the registry directory and the witnesses to a scratch machine.
2. Without the key you "lost", run **A** if n > k, else **B**, from this page alone.
3. Time it. Write down every step where you had to guess.
4. Check the end state: posture reconfirmed, the old key refused, a re-engagement / transition leaf
   present, and the notice at start-up.

An operator who has lost a key must be able to get an operational cell back by following this
page alone; a drill that needs anything else is a defect of the page, to be fixed here.
