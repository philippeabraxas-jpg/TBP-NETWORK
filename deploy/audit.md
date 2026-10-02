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
    -log /var/lib/tbp/registry -vkey-file cell_log.pub [-index N] [-reveal]
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
| Library producers with a `Journal` option, wired by the daemon that runs them: promotion controller (`TBPP1`), anchorer, backpressure stop leaf | `KindPromotion`, `KindAnchor`, `KindBackpressure` | `Journal` option (nil = bare leaf). The stop leaf and the episode leaf are written around the backpressure lock: a journal that refuses ⇒ the leaf is skipped (`+leaf-write-failed` in the alarm) and the lock holds. |

Every other producer (supervisord, dev-mode flags, telemetry and translator
metrics, …) still appends
a bare leaf: its leaves have no journal entry and `tbp-audit` has nothing to say
about them. Wiring them is tracked in #275, one producer at a time.
