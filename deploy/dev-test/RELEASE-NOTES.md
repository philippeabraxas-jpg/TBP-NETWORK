# TBP-NETWORK — DEV-TEST release notes

_The first release of this repository. A **pre-release for testing, not for production.** The version number is chosen when
the tag is created. Part of [deploy/dev-test](README.md)._

> **Do not use this release to govern real agents or real data.** It uses throw-away keys, a seed file in place of an HSM, and
> no key ceremony. It exists so that you can run TBP on three machines, try to break it, and tell us what happened.

## What this release is

TBP-NETWORK is the network-level implementation of the [Teleological Bounding Protocol](https://github.com/philippeabraxas-jpg/Responsible-Alliance-Protocol):
a decision made by a **cell** before an agent acts, a **token** that a **server** checks before it lets the action through, and a
log that records both. This release lets you stand that up and attack it:

| | |
|---|---|
| **M1** | the cell: `brokerd` and its OPA |
| **M2** | an application server: `pepd` (the policy enforcement point), its OPA and a small application |
| **M3** | an agent |

It runs the **real binaries with the real enforcement** (quorum of controllers, operator roles, signed rules, mutual TLS,
fail-closed starts, measured boot). What is simplified is the key ceremony, and nothing else: see
[README.md](README.md#what-is-simplified-and-what-is-not).

You get:

- the scripts and guides to deploy the three machines from fresh Debian 12 ([site.md](site.md)) or the cell alone ([solo.md](solo.md));
- a **live console** that shows the path of each request across the three machines ([console.md](console.md));
- templates that create the three machines in **Azure** or **AWS** ([cloud/](cloud/README.md));
- the report of the first real run ([reports/2026-11-08-azure.md](reports/2026-11-08-azure.md)) and the plan for the next
  ([reports/aws-test-plan.md](reports/aws-test-plan.md));
- the binaries (`pepd`, `brokerd`, `anod`, `supervisord`, `opawatchdog`, `quorumproof`, `tbp-audit`), for linux/amd64 and
  Debian 12, built by GitHub Actions with a signed SLSA provenance and an SBOM ([how to verify](../../SECURITY.md#verifying-a-release)).
  The DEV-TEST scripts build the daemons from the source you check out (they need Go and a C compiler); the attached binaries
  are the same code.

## What was run for real, and what it showed

One run, by one person, by hand, on **Azure** (three `Standard_D2s_v5`, Debian 12, Sweden Central), on 8 and 9 November 2026.
Full detail, with what is not established: [the report](reports/2026-11-08-azure.md).

**It works end to end.** Steps 1 to 14 of [site.md](site.md) were played on the three machines: an agent refused without a plan,
approved by an operator, executed through `pepd` on another machine; replay, wrong scope and forged token detected; the server
closed by one controller and reopened by two; a class W action refused without the controllers' proof and accepted with it; an
agent refused with another agent's certificate or none; a restarted `pepd` coming back `refused` and blocking until a quorum
reconfirms it.

**It refused every change to a file it measures.** 13 changes (M1 and M2: the agent registry, the quorum, operator roles, a
controller's key, the agents' certificate authority, the signed rules and their verification key, a measured file, the issuer keyring,
the admission switch of OPA) stopped the start, each with a message naming its cause. Altering one byte of the rule bundle breaks
the archive before any signature check; changing a rule and repacking the archive is refused by the signature. A setting that is
deliberately outside the commitment (the size of OPA's admission queue) starts, as designed.

**A hard stop did not let anything through.** With `pepd` killed (`kill -9`) right after a record was written to its journal, the
agent got no verdict and nothing was executed.

**Floods of invalid requests left no loss in what we checked.** 22,000 requests with an invalid, non-empty token: every one has its
journal record and its leaf in the log (`tbp-audit verify`), with no alarm of the durability path. A valid request sent during a
further flood of 6,000 got its verdict with its leaf written; that flood was not checked afterwards.

## Numbers from that run

One setup, a few dozen requests per measure, taken by hand. **They are not a performance claim.** The causes of the two largest are
**not explained**.

| Measure | Value |
|---|---|
| Cell decision (a request refused for want of a plan) | p50 553.5 ms, spread 3 ms over 60 requests |
| Cell decision, accepted: class I / class W | about 780 ms / 1.04 s |
| `pepd` verdict, malformed token (the cheapest) | p50 7.7 ms |
| `pepd` verdict, valid token | 217 to 289 ms over nine samples on two days |
| OPA alone (`tests/opa_latency`, 2 CPUs) | one flow: 0 `opa-timeout` in 4,000 requests; 4 at once: 3.3 % |
| `init` on M1 / M2 / M3 | 19 s / 1 s / 0 s (M1 with a warm Go cache) |

## Known limits — read before you test

These are what the run found. A finding that is one of them is welcome as an ordinary issue.

1. **A given agent can have two decisions in flight; beyond that the cell refuses.** With the default settings, parallel decisions
   of one agent were refused with `opa-overloaded` as follows: 0 % at 1 and 2 at once, 2 % at 3, 27 % at 4, 87 % at 16; with
   `TBP_OPA_MAX_INFLIGHT=4`: 0 % at 4, 67 % at 16. The refusals are immediate and explicit, and are not an OPA fault. The knobs
   are `TBP_OPA_MAX_INFLIGHT` and `TBP_OPA_SUBJECT_SHARE` ([deploy/cellule.md](../cellule.md)). One subject, one 2-CPU machine;
   how long a place is held is **not measured**. This is a limit of this version, not a sizing for production
   ([#349](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/349)).
2. **A decision takes about half a second to a second, and a valid token about a quarter of a second at `pepd`.** The cell
   writes the decision's leaf into the signed log before it answers; `pepd` runs in its default bounded asynchronous mode and
   still takes 217 to 289 ms for a valid token. We have not separated the steps and do not know why. The repository's own friction thresholds put an upper bound of 50 ms (p95) on a
   token verification (`tests/p1_friction/friction_thresholds.yml`); valid tokens took 217 to 289 ms here.
3. **A hard stop at the wrong moment leaves an orphan record, and nothing closes it.** Killing `pepd` right after a record is
   written to its journal left an orphan (a journal record whose leaf is not in the signed log) in 3 of 3 tries; 0 of 1 when the kill
   came 0.3 s later. `tbp-audit verify` finds and names it and exits 1; a restart does not close it; no tool does
   ([#347](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/347)). The window's width is not measured.
4. **Invalid tokens are not rate-limited.** An invalid, non-empty token reaches `pepd` and costs about 360 bytes on disk (journal and
   registry). 22,000 of them caused no loss and no alarm, at 73 to 164 requests a second from a client that may have been the
   limit (6,000 more were not checked afterwards). A faster flood, a full disk, and a valid request waiting behind a long flood were **not tried**
   ([#348](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/348)).
5. **Single points.** One cell: if it is down, governed actions stop within about a minute (tokens live 30 to 60 s). That is
   fail-closed by design. See also the [README](../../README.md#roadmap-right-sized-deployment-scales) ("Honesty about where this stands").

## What was not tested

- **AWS.** The AWS template and guide have **never been run against a real account**. Azure's template was deployed once.
- **The files of the cell that it does not list among those it measures** (the issuer seed, the cell's TLS certificate and key, the
  key of the audit journal, settings outside the security posture). Whether changing them is noticed is not known.
- **Class F agents** (no approval): the site pack carries the certificates of the class I and class W agents only.
- Several agents at once, a disk that fills, a network that drops, key custody, a real genesis ceremony, remote administration.

## What we ask of you

Run the site, attack it, and **send us your numbers and comments for each environment you try** (`scripts/devtest/site.sh m1|m2|m3
report`, and a **Dev-test feedback** issue whose title starts with `[dev-test]`; see [README.md](README.md#telling-us-what-you-found)).
Anything exploitable (a way past a refusal, a silent acceptance, a leaked secret) goes **privately**, as
[SECURITY.md](../../SECURITY.md) says, not into a public issue.

## After this release

The issues #347, #348 and #349 above, then the same test on AWS with timings, then a production-oriented release. Nothing here
promises a date.
