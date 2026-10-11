# The monitor: where it is, how to read it, how to use it

_Version française : [console.fr.md](console.fr.md). Part of [deploy/dev-test](README.md); the machines are described
in [site.md](site.md)._

> **There is no screen to open.** The "console" of the DEV-TEST site is three commands you type in a terminal **on M1**,
> the cell. Nothing listens for it, there is no URL and no login: whoever can run `site.sh` as the user who ran
> `m1 init` is the operator. (What a real console should be is an open question, [#329](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/329):
> tell us what you missed.)

## What do you want to know?

| You want to know | Run | On | It shows |
|---|---|---|---|
| Is the cell healthy, what has it decided so far, is anything waiting? | `scripts/devtest/site.sh m1 watch` | M1 | a status page, 7 lines |
| What happened to **my request**: who stopped it, and why? | `scripts/devtest/site.sh m1 trace` | M1 | one timeline per request, across the three machines |
| What am I about to sign, and is it what the cell sealed? | `scripts/devtest/site.sh m1 sign <agent> <action> <resource>` | M1 | the plan in clear, a recomputed hash, a question |
| Are the processes of this machine up? | `scripts/devtest/site.sh m1\|m2 status` | M1, M2 | up / DOWN, counters |
| What does this machine listen on? | `scripts/devtest/site.sh m1\|m2\|m3 listeners` | any | ports and addresses |
| What do I send you when something went wrong? | `scripts/devtest/site.sh m1\|m2\|m3 report` | any | numbers, no secret |

## Getting there

1. Log in to **M1** (SSH) as the user that ran `site.sh m1 init`, in the repository checkout. If you gave `init` another
   home, set `TBP_SITE_HOME` to it first (default `~/tbp-site-m1`).
2. Everything below is run from there. The commands only **read** (`watch`, `trace`) or ask you before they do anything
   (`sign`); none of them changes the state of the test.
3. To see what **M2** and **M3** recorded, you bring their files to M1 (the monitor reads files; it does not call
   those machines):

```
# on M2 and on M3, once you have made your requests
scripts/devtest/site.sh m2 trace-export      # → ~/tbp-site-m2/trace-m2.tgz
scripts/devtest/site.sh m3 trace-export      # → ~/tbp-site-m3/trace-m3.tgz
# on M1
scp <user>@<M2>:tbp-site-m2/trace-m2.tgz <user>@<M3>:tbp-site-m3/trace-m3.tgz .
scripts/devtest/site.sh m1 trace --from trace-m2.tgz --from trace-m3.tgz
```

Without `--from`, `m1 trace` shows only what M1 itself saw: a request the cell refused is complete, an allowed one ends
*TOKEN ISSUED … not presented* because M2's and M3's files are not there — that is normal, not a fault. Do the export
again after new requests: an archive is a snapshot.

## Reading `m1 watch`

```
cell cell-site · 2026-10-11T11:05:27Z · read-only view (a line says UNKNOWN when its source does not answer)
processes  : opa up · brokerd up
rules      : 601b4836a09855f4… (signed bundle) · OPA healthy · unanswered 0 · shed 0
decisions  : 12 requests · 4 allowed · 8 denied (quorum 0, plan 5, envelope 0)
faults     : none (issuance, ledger leaves, translation)
epoch      : single cell, no fencing (epoch 0)
pending    : 2 plan(s) waiting (hash only — the cell keeps no plan in clear)
audit      : 14 record(s) checked, 0 failure(s) (hash match only; inclusion in the signed log: tbp-audit verify -log …)
```

| Line | Means | Worry when |
|---|---|---|
| `processes` | OPA (the rules engine) and `brokerd` (the cell) are running | `DOWN` |
| `rules` | the first 16 hex digits of the signed rules in force, whether OPA answers, whether it is shedding requests | `STALLED`, `unanswered` or `shed` growing |
| `decisions` | requests the cell has decided since it started, and the refusals by cause | `quorum` or `plan` growing when you did not expect it: someone is asking without an approved plan |
| `faults` | failures **of the cell itself** (could not sign a token, could not write a ledger leaf, could not translate) | anything but `none`: a fault is never a normal refusal |
| `epoch` | the cell's epoch; a single cell has no fencing | — |
| `pending` | plans submitted and not yet approved, by hash only: the cell keeps no plan in clear, so what a plan *says* is read where you sign (`m1 sign`), not here | a number that never goes down |
| `audit` | the cell's audit journal still matches its ledger leaves | `! the journal does not verify` |

**`UNKNOWN` and `DOWN` are never green.** If a source does not answer, its line says so and the command **exits
non-zero**, so a script can rely on it. A stopped cell prints `UNKNOWN` on every line. `--every 5` repeats the view every
5 seconds (stop with Ctrl-C).

## Reading `m1 trace`

```
t-1791718709-30e71f   token presented again: read doc-1
  +0.000s  M3  agent     token presented again: read doc-1
  +0.015s  M2  app       request received: read doc-1 with a token   [from 10.0.0.9]
  +0.017s  M2  pepd      verdict deny replay   [posture monitor · forwarded true · 0.7 ms]
  +0.017s  M2  app       EXECUTED   [HTTP 200]
  → EXECUTED — although pepd's verdict was replay: in the monitor posture pepd records and blocks nothing
```

**The header** is the request's **trace id**, printed by `m3 act` and `m3 call` (`[trace t-…]`). The same id travels
to the cell and to the application in the header `X-TBP-Trace-Id`, which is how three machines' records are joined.

**Each line:** `+offset` from the first event · the machine (`M1` cell, `M2` server, `M3` agent) · the component · what
it did, with details in brackets.

| Component | Machine | Is | Its line tells |
|---|---|---|---|
| `agent` | M3 | the script that plays the agent | what it asked, with which certificate, what it got back |
| `brokerd` | M1 | the cell | `ALLOW`/`DENY` and the **reason**; in brackets: the agent, the action, the **certificate** presented, mTLS or Unix socket, the **address** it came from, the time it took, the token id (`jti`) |
| `transport` | M1 | the TLS layer in front of the cell | a connection that failed **before** it became a request (no or wrong client certificate) |
| `pepd` | M2 | the enforcement point | its **verdict** on the token, and the posture (`monitor`, `closed`, `refused`) and `forwarded` |
| `app` | M2 | the small application | the request it received, and what it did: `EXECUTED` or `REFUSED` |

**The last line (`→`) is the answer to "what happened?":**

| It says | Meaning |
|---|---|
| `EXECUTED` | the application acted |
| `EXECUTED — although pepd's verdict was …` | `pepd` said no but the posture is `monitor`: it records and blocks nothing. Close it to block ([monitor-to-closed.md](../monitor-to-closed.md)) |
| `REJECTED by the cell (M1) — <reason> — <where>: <why>` | the cell refused: no token was issued. The `where` names the stage (identity, plan contract, quorum, policy…) |
| `REJECTED at the TLS handshake (M1)` | no (or wrong) client certificate: the cell never saw a request |
| `REJECTED by pepd (M2) — <reason> …` | the token was bad, replayed or for something else, **and** the posture blocks (`closed`/`refused`) |
| `REJECTED by the application (M2) — no-token` | the request carried no token |
| `TOKEN ISSUED by the cell, not presented …` | the agent got a token and did not use it (or M2's file is missing) |
| `INCOMPLETE — no end seen …` | a machine's file is missing: add its `--from` |

Every reason code (`opa-deny`, `plan-binding-required`, `replay`…) is explained in the ending of a rejected request;
the full catalogue is [`scripts/devtest/reasons.tsv`](../../scripts/devtest/reasons.tsv).

**The section "without a trace id".** A client that is not our scripts — `curl`, a scanner, a red team — sends no id.
Those requests are still seen by the cell (`brokerd` line, with the certificate and the address) and by the application,
and are listed apart, one line per event, oldest first. This is where to look to see **your own attack**.

## Using it

| To | Do |
|---|---|
| see one request only | `m1 trace … --id t-1791718709-30e71f` |
| follow while you test | `watch -n 5 scripts/devtest/site.sh m1 watch` (or `m1 watch --every 5`); for `trace`, re-export and rerun — it works on snapshots |
| sign the plan of an action | `m1 sign agent-i read doc-1`: it shows the plan, recomputes its hash, asks you to type `sign`. Anything else signs nothing. `grant` is `sign --yes` (no questions, the hash is still recomputed) |
| close or reopen `pepd` | `m1 mode-proof closed\|monitor` on M1, then `m2 mode … --proof <file>` on M2: one controller to close, two to reopen |
| check the audit trail against the signed log | `tbp-audit verify -records … -key … -log … -vkey-file …` (see [audit.md](../audit.md)) |

That is all: **you cannot approve, revoke or change anything from `watch` or `trace`.** The only places where a person
acts are `m1 sign` and `m1 mode-proof`, and both say what they are about to do.

## Recipes

**"My request was refused and I do not know why."** Run `m3 act …`, note the `[trace t-…]`, export M2 and M3, then
`m1 trace --from … --id t-…`. Read the last line.

**"I attack the cell with `curl` and want to see what it saw."** Run your attack, then `m1 trace`: your requests are
under *without a trace id*, with the certificate you presented and your address. A connection refused at the TLS
handshake shows as `transport … TLS handshake failed`.

**"I closed `pepd`: what changes?"** Make the same request before and after. Before: `EXECUTED — although pepd's
verdict was replay`. After: `REJECTED by pepd (M2) — replay`.

**"Nothing is shown."** `m1 trace` prints `no request recorded yet` until a request has been made *since the cell
started with the trace on* (a cell started by an older `m1 init` does not trace: run `m1 init` again on a clean home).

## What it does not show

- **Clocks.** The three machines' clocks differ: offsets *between* machines are indicative; the order *within* a
  machine is exact. A refused TLS handshake is attached to the request that explains it **by time** (the cell's log has
  whole seconds, within 3 s), and the line says so.
- **`pepd`'s own view.** The `pepd` lines are the verdict it returned to the application. `pepd` itself is not modified
  and M2 has no development switch.
- **The content of a plan.** `watch` shows plans by hash; their content is shown when you sign.
- **Secrets.** No token, key or seed is ever recorded. The files do hold agent names, resources, certificate names and
  addresses: **read an archive before pasting it into a public issue.**
