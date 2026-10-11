# deploy/dev-test — try TBP, attack it, and tell us what happened

_Version française : [README.fr.md](README.fr.md)._

> **Not for production.** Everything here uses throw-away keys, on machines you can lose, with no real data and no
> real agent behind them. It exists so that you can try to break TBP before a production release does.

TBP is meant to be run, and attacked, before it is trusted. This page is the way in: a deployment that is simple
enough to stand up in minutes — keys, genesis and rules are generated for you — and still runs **the real binaries
with the real enforcement**: the same quorum, the same roles, the same signed rules, the same fail-closed starts.
The more people try to break it now, the fewer gaps a production release will carry. The CI and the selftest ask
whether the code is sound; this asks whether the whole thing **works**, and whether you can get past it.

## Two ways to run it

| | **Site** — three machines | **Solo** — one machine |
|---|---|---|
| Page | **[site.md](site.md)** | [solo.md](solo.md) |
| What runs | M1 the cell (`brokerd`, OPA), M2 an application server (`pepd`, a small application), M3 an agent | the cell only (`brokerd`, OPA) |
| What it tests | **that it works end to end**: an agent enrolled by its certificate, a decision over mutual TLS, a token checked by a server, the server's posture governed by the controllers — and the network between them | the cell's decision: admission, plans, quorum, signed rules, the fail-closed start |
| What it does not | key custody, separation between real people, a genesis ceremony | tokens at a server, enrolment, the network |
| For | the functional test and the red team: **this is the DEV-TEST release** | a quick look at the cell |

**Watching what happens:** open the **live console** in a browser — after `m1 up`, one address shows the path of every request across the three machines, the state of each component and the latency of each step. [console.md](console.md) says where it is, how to read it and how it measures.

If you try one thing, try the site: it is the one that matches how TBP is deployed.

## What is simplified, and what is not

| | In both | Why |
|---|---|---|
| Keys, genesis | generated for you, no ceremony, no HSM | **simplified**: custody and the separation of real people are not tested here |
| Decision trace | Site profile only: each machine records the requests it sees, `m1 trace` lays them out (who asked, what each component decided, why) | **added for testing**, a second development switch on the cell (the trace holds names and intents in clear); `pepd` is untouched |
| Issuer key | a seed file instead of an HSM — on the cell only | **simplified**, a development switch in use: the cell declares `/etc/tbp/DEV_ENVIRONMENT` and raises a high-priority alarm at every start |
| Quorum, roles | `k = 2` of 3 controllers, four operator keys with roles | **not simplified** |
| Rules | the example bundle, restricted capabilities, signed; OPA refuses an altered one | **not simplified** |
| Provisioning, measured boot | on: a changed trust file or scale stops the start | **not simplified** |

## Telling us what you found

We want your numbers and your comments — including "I got stuck here" — **for each environment you try**.

- **Numbers.** Every machine has a `report` command (`scripts/devtest/site.sh m1|m2|m3 report`, or
  `scripts/devtest/devtest.sh report` for solo). It records the system, the versions, how long things took, the
  counters and the latencies, and the free-text environment label you gave at `init`, so that we can tell
  environments apart. It contains no key, seed, path, address or host name. Paste it.
- **Comments.** A public GitHub issue, using the **Dev-test feedback** template (the title starts with `[dev-test]`):
  a step that did not work, a doc that is wrong, a behaviour that differs from what is written, your timings, a
  suggestion. What makes it useful: the exact command, what you expected, what happened, and the reports.
- **Anything exploitable** — a way past a refusal, a silent acceptance, a leaked secret — goes **privately**, as
  [SECURITY.md](../../SECURITY.md) says, not into a public issue.

Known limits are written in the [README](../../README.md) ("Honesty about where this stands"), in
[CHANGELOG.md](../../CHANGELOG.md) and in [governed-acts.md](../governed-acts.md): a finding that is one of them is
welcome as an ordinary issue.
