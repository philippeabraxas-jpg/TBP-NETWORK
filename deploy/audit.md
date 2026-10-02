# Audit records — where the cleartext lives, how to verify it (#271)

_Version française : [audit.fr.md](audit.fr.md)._

Registry leaves are **hash-only** (§6.2): `sha256(salt ‖ record)`, never the
record. The salt and the record stay with the **producer** (the daemon that
wrote the leaf). This page fixes the two things that were missing: **the file
the cleartext lives in**, and **the command that proves a record belongs to a
leaf**. The audit reader of the admin tool (#86) shows what this page defines —
nothing else.

## Decision

Option 1 of #271: **one local, encrypted record journal per daemon.** The
cleartext never leaves the cell; the registry and the master chain stay
hash-only. (Rejected: cleartext in the registry — contradicts hash-only;
no cleartext at all — the audit would show only hashes.)

## The journal

`registry.RecordStore` — append-only, JSON lines, one entry per leaf:

```
{"v":1,"leaf":"<hex of the exact leaf bytes>","nonce":"<b64>","ct":"<b64>"}
```

- `leaf` is public (the leaf is in the log) and indexes the entry without a key.
- `ct` = AES-256-GCM(journal key, `len(salt) ‖ salt ‖ record`), with the **leaf
  bytes as authenticated data**: an entry moved under another leaf, or a leaf
  edited in the file, no longer decrypts.
- `Put` refuses a record that does not hash to the leaf, a salt < 16 bytes and
  a zero timestamp. Every write is fsynced.

**Write order (fail-closed).** `registry.AppendSealed` writes the record to the
journal **before** appending the leaf. If the journal refuses, **no leaf** is
written: there is never a leaf whose cleartext does not exist. The reverse
(record written, leaf not appended) leaves an **orphan** record: harmless, and
reported by the verification.

**One documented exception: the leaves written around the backpressure lock.** The
stop leaf (`KindBackpressure`) and the durability-episode leaf (`TBAD1`) are the
proof that the cell stopped, and the journal usually sits on the disk that just
filled up. If the journal refuses their cleartext, the leaf is **still written, bare**
(hash only), and the daemon says so: the backpressure alarm reason gets
`+journal-write-failed` (pepd logs `ALARME journal d'audit` for the episode leaf). The
lock holds either way. The leaf is then listed by `tbp-audit verify -coverage`. (The
decision made in #275: a stop with no trace in the signed log is worse than a stop
whose cleartext is missing and flagged.)

## The journal key

A 32-byte secret, hex in a `0600` file (a wider mode is refused at load). It
protects against reading **the journal file alone**. If it sits on the same
disk as the journal, whoever takes the disk takes both: keep it in the HSM or
on a separate volume (limit, not a guarantee). Generate it once:

```
tbp-audit keygen -out /etc/tbp/records.key      # never overwrites
```

## Verifying — `tbp-audit`

```
tbp-audit verify -records records.jsonl -key records.key \
    -log /var/lib/tbp/registry -vkey-file cell_log.pub [-index N] [-reveal] [-no-coverage]
```

Without `-log`, only `sha256(salt ‖ record)` = leaf hash is checked (`hash-ok`).
With `-log`, the leaf must also be **in the log** under a **signed checkpoint**
(public key required — an unverified checkpoint is not a proof), with an
RFC 6962 inclusion proof verified against its root (`inclus index=N`).

| Status | Meaning |
|---|---|
| `inclus index=N` | record matches the leaf, leaf proven in the log |
| `hash-ok` | record matches the leaf hash; log not consulted |
| `ORPHELIN` | record journaled, leaf not in the log |
| `HASH-DIFFÉRENT` | cleartext does not hash to the leaf (altered record) |
| `REJETÉ` | checkpoint signature / inclusion proof rejected |

Exit code: `0` all verified, `1` at least one failure, `2` usage or unreadable
journal (wrong key, altered line — a partially readable journal does not pass
for a complete one). The cleartext is printed only with `-reveal`.

**The reverse check: coverage, ON by default with `-log`.** `verify` goes from the journal to the
log: it sees an orphan record, but **not** a leaf that sits in the log with no journal entry — nor
an entry that was **deleted** from the journal. With `-log`, `verify` therefore also re-reads
**every leaf of the log** under the signed checkpoint and lists those with no journal entry
(`SANS-CLAIR`), exit code `1` if there is any:

```
tbp-audit verify -records records.jsonl -key records.key \
    -log /var/lib/tbp/registry -vkey-file cell_log.pub
feuille index=412 kind=3 cell=cell-a ts=… SANS-CLAIR : aucune entrée de journal
```

Before, this check was opt-in (`-coverage`) and `verify -log` answered "0 failures" on a journal
whose last entry had been deleted (third-party review of 2 October, 4.5). Now `-no-coverage`
turns it off **explicitly**, and `verify` says so on stderr: *"0 failures" does not mean "journal
complete"*. `-index N` (a targeted check) skips it with the same warning unless you add
`-coverage`; without `-log`, only the hash match is checked, and the warning says that too.
`-coverage` is still accepted. Upgrading: a script that ran `verify -log` on a log with leaves
older than the journal now exits `1`; pass `-no-coverage` knowingly, or accept the list.

Such a leaf is expected in two cases only: a leaf **older than the journal**, and the
**documented exception** below (journal refused on a full disk). Anything else is a
producer that is not wired — the selftest runs this check on every daemon's log.

## Producers

Wired so far:

| Producer | Leaves | Configuration |
|---|---|---|
| `pepd` — decisions: validator (`TBPD1`/`TBPD2`), OPA client, quota cuts, dry-run refusals | `KindDecision` | `TBP_AUDIT_RECORDS` (journal path) + `TBP_AUDIT_RECORDS_KEY_FILE` (`tbp-audit keygen`). **Required** by `pepd` (no journal ⇒ it does not start). A journal that refuses a write ⇒ no leaf ⇒ an allow becomes a deny (`leaf-write-failed`). |
| `pepd` — ano rewrite audit (`TBAN1`, #178) | `KindTelemetry` | same journal (shared) |
| `pepd` / `brokerd` — state and alarm leaves: fail-closed trips and clears (`TBFF1`), clock alarms (`TBPC1`), posture switches (`TBPM1`), OPA revision alarms (`TBPR1`), dry-run telemetry (`TBPF2`) | `KindTelemetry` | same journal (shared) |
| `brokerd` — decision chain (`TBPD1`), OPA client, plan contracts (`TBPL1`/`TBPL2`, signature included), class-W quorum (`TBPQ1`) | `KindDecision`, `KindContract`, `KindQuorum` | its own `TBP_AUDIT_RECORDS` + `TBP_AUDIT_RECORDS_KEY_FILE` (**required**: `brokerd` does not start without them). Same fail-closed order: journal refuses ⇒ no leaf ⇒ the emission is refused. |
| `pepd` / `brokerd` / `anod` — provisioning guard (`TBPL3`: genesis, boot, transition, refusal, re-engagement) | `KindManifest` | same journal (shared); `anod` has its own `TBP_AUDIT_RECORDS` + `TBP_AUDIT_RECORDS_KEY_FILE` (**required**: `anod` does not start without them). A journal that refuses ⇒ no leaf ⇒ the guard refuses the boot. |
| `pepd` — measured-boot manifest (`TBPL2`) | `KindManifest` | same journal (shared) |
| `brokerd` — epoch tracker (`TBPE1`), `pepd`'s async writer episode leaf (`TBAD1`) | `KindEpoch`, `KindTelemetry` | same journal (shared) |
| Library producers with a `Journal` option, wired by the daemon that runs them: promotion controller (`TBPP1`), anchorer, backpressure stop leaf | `KindPromotion`, `KindAnchor`, `KindBackpressure` | `Journal` option (nil = bare leaf). The stop leaf and the episode leaf are written around the backpressure lock: a journal that refuses ⇒ the leaf is **still written, bare** and the alarm says `+journal-write-failed` (see "one documented exception"); the lock holds. |
| `supervisord` — monitor alerts (`TBPS1`, salt included) | `KindSupervision` | its own `TBP_AUDIT_RECORDS` + `TBP_AUDIT_RECORDS_KEY_FILE` (**required**: no journal ⇒ `supervisord` does not start). A journal that refuses ⇒ no leaf ⇒ no alert is notified. |
| `opawatchdog` — OPA restart decisions (`TBPS1`, events 6/7, salt included): `opa-restart-requested` (written **before** the restart runs), `opa-restart-failed`, `opa-restart-budget-exhausted` (#275) | `KindSupervision` | its own chain and journal: `TBP_OPAWD_REGISTRY_DIR`, `TBP_OPAWD_AUDIT_RECORDS` + `TBP_OPAWD_AUDIT_RECORDS_KEY_FILE` (**required**: no journal ⇒ `opawatchdog` does not start). A journal that refuses ⇒ no leaf ⇒ **no restart** (`untraced-refused`). |
| `pepd` / `brokerd` — dev-escape-hatch flags (`TBDV1`) | `KindTelemetry` | same journal (shared); a journal that refuses ⇒ the start is refused |
| `tmetrics` — translator measurement (`TBTM1`) | `KindTelemetry` | `TBP_AUDIT_RECORDS` + `TBP_AUDIT_RECORDS_KEY_FILE` (**required**), pointing at the journal of the service (pepd or brokerd) that owns the registry it appends to |
| `brokerd` — human arbitration of degraded requests, **opt-in** with the guard (#275): enqueue, operator decision (approve / refuse, with the operator's key id) and single-use consumption (`TBAR2`, hash-only: request id, subject, never the content) | `KindTelemetry` | same journal (shared); a journal that refuses ⇒ no effect (nothing queued, decided or consumed) and the `arbiter-leaf-write-failed` alarm. **Read back at start** to restore the queue (approvals only if the leaf is in the signed log) |
| `brokerd` — mirror promotions, **opt-in** with the guard (#275): every decision of `PromotionController` on a mirror receipt, accepted or refused (`TBPP1`) | `KindPromotion` | same journal (shared); a journal that refuses ⇒ the refusal is returned as untraced and nothing is promoted. **Read back at start** to restore the current promotion (only if its leaf is in the signed log and today's signed anchors still cover it) |
| `brokerd` — translator degradation guard, **opt-in** `TBP_TRANSLATOR_GUARD=1` (#275): down / recovered episodes and every refusal while degraded (`TBTD1`) | `KindTelemetry` | same journal (shared); a journal that refuses ⇒ no leaf and the `translator-leaf-write-failed` alarm, the failure direction stays deny |
| `pepd` — passport telemetry pipeline, **opt-in** `TBP_TELEMETRY=1` (#275): window aggregator (`TBAG1`, one leaf per sealed window, empty ones included), anti-dribble detector (`TBAD1`), retention purge (`TBRP1`) | `KindTelemetry`, `KindTelemetryAlert`, `KindRetentionPurge` | same journal (shared); a journal that refuses ⇒ no leaf and the `leaf-write-failed` alarm, never silence |
| Library producers with a `Journal` option, not yet run inside a daemon: telemetry exporter sink (`TBTM1`, one `fsync` per record — wire it knowingly) | `KindTelemetry` | `Journal` option (nil = bare leaf) |

Every producer of leaves in this repository now has a journal seam, and every
daemon that writes leaves requires its journal. A library producer is bare only
until its host wires `Journal` — `pepd` runs the telemetry pipeline (opt-in) and
`brokerd` the translator degradation controller (opt-in); nothing in-tree runs
the telemetry exporter sink inside a daemon yet.
