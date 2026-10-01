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

This page and the tooling are the common base. Wiring each producer to
`AppendSealed` (instead of appending a bare leaf) is tracked separately; until
a producer is wired, its leaves have no journal entry and `tbp-audit` has
nothing to say about them.
