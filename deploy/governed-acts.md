# Governed acts: what each one costs, and why

_Version française : [governed-acts.fr.md](governed-acts.fr.md)._

TBP asks a different effort for two kinds of act, on purpose.

- An act that **restricts** makes the cell stricter: it closes, cuts, refuses, withdraws. Doing it by mistake
  costs some availability, and it can be undone. It must be **easy and fast**: one person, even when most
  controllers are unreachable.
- An act that **widens** lets the cell allow more: it approves, reopens, resumes, hands over authority. Doing it
  by mistake, or under pressure, lets through what should have stayed blocked. It must be **hard**: several
  signatures from several keys.

When an act could be either, it counts as **widening**, unless it can be shown to only tighten. The practical
test when you add an act: ask what the worst a wrong or forged call can do is. If the answer is "the cell
applies the rules it already has", it restricts.

This page lists every act the cell takes today, which side it is on, and what it takes. It is the reference to
read before adding one.

## The acts

| Act | Where | Side | What it takes |
|---|---|---|---|
| Close the network (monitor → closed) | `pepd` `POST /v1/mode` | restricts | `TBP_MODE_RESTRICT_QUORUM_MIN` controller signatures (default 1, never more than k); leaves its own leaf and raises `mode-closed-reduced-quorum` |
| Reopen it (closed → monitor), leave `refused` | `pepd` `POST /v1/mode` | widens | k controller signatures, always |
| Submit a plan | `brokerd` `plan/submit` | neutral: nothing runs until it is approved | from k = 2, a signature by a key that holds `submit`; the submitter never approves that plan |
| Approve a plan | `brokerd` `plan/approve` | widens | class F or W: k distinct keys that hold `approve`; class I: one; never the submitter's key |
| Revoke a plan | `brokerd` `plan/revoke` | restricts | one signature by a key that holds `revoke` |
| Refuse a degraded request | `brokerd` `degraded/decide` | restricts | one signature by a key that holds `arbitrate` **or** `revoke` |
| Approve a degraded request | `brokerd` `degraded/decide` | widens (admits that one request) | one signature by a key that holds `arbitrate` |
| Signal presence | `brokerd` `degraded/presence` | neutral | a key that holds `arbitrate` |
| Lift a fail-closed condition of class W | `pepd` `POST /v1/failclosed/clear` | widens | k controller signatures bound to the condition |
| Lift a fail-closed condition of class F or I | `pepd` `POST /v1/failclosed/clear`, or automatically after probes | widens | nothing but access to the admin socket (spec §5.3: only class W takes a quorum); automatic lifting is refused for class W |
| Renew the epoch lease (multi-cell) | `brokerd` `POST /v1/epoch/renew` | widens: keeps the cell's authority alive | the controllers' quorum, signed out of band |
| Promote the mirror cell | `brokerd` `mirror/promote` | widens: hands authority over | a receipt signed by the mirror cell and the quorum's anchor |
| Change what the cell trusts (rules, trust files, scale, posture) | provisioning witness, at start | either | k controller signatures bound to the exact change, and a cold restart: **the same cost in both directions** (see below) |

Roles are set per key in `operators.json` ([scale-2.md](scale-2.md) step 3). A key that signs for a role it does
not hold is refused with a named reason, and the refusal leaves a leaf.

## What is not asymmetric yet

- **Tightening the trust files costs as much as loosening them.** Withdrawing a stolen operator key, or raising
  `k`, is a provisioning transition like any other: k controllers and a cold restart. Until then the stolen key
  can still be neutralised plan by plan (`plan/revoke`, one signature), but it stays in the keyring. A
  transition that can prove it only tightens, and so takes fewer signatures, is not built.
- **A class F or I fail-closed condition is lifted without a proof.** That is what the spec says (§5.3), and the
  admin socket is the access control. If you do not want that on a cell, register the condition as class W.
- **Approving a degraded request takes one signature.** It admits one request, once, after which the request goes
  through the usual chain. A cell that wants more can keep `arbitrate` on a single key and watch the leaves.

## Adding an act

1. Say which side it is on, with the worst a forged call can do.
2. Give the side its price: restricting is one key or a reduced quorum; widening is k keys.
3. Put the price in the code that applies it (`brokerd`, `pepd`), never in a wrapper or a script that a direct
   call would skip.
4. Leave a leaf for the act, and one for each refusal.
5. Add it to this table.
