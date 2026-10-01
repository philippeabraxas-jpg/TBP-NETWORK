# deploy/design-promotion.md — target architecture: bundle anchoring and canary promotion (§7.4)

_Version française : [design-promotion.fr.md](design-promotion.fr.md)._

**Status: design, not implemented. To be settled at the first multi-cell deployment** (issue #233; it
closes R-15 of #210). Nothing here is a guide to run: it records the architecture we want so that the first
deployment answers its open questions instead of rediscovering them.

## What exists today, plainly

- `src/cluster/promotion.go` (`PromotionController`) is a **library**: it checks a signed receipt — the
  candidate's signature, the bundle hash against the anchored one, the healthy window — and writes a
  `KindPromotion` leaf either way.
- The anchored hash and the healthy window come from a `MasterAnchorSource` interface. It has **no
  implementation outside tests** (the `masterStub` of the `fencing` selftest), and `NewPromotionController`
  has no production caller.
- The master's anchoring (`src/registry/anchor.go`) commits the **head of a cell's log**, not a bundle and
  not a window. The master holds, at best, a hash — never the bundle's bytes.
- `Receipt.ReceivedAt` is signed by the candidate and parsed, but **never compared to anything** (R-15): the
  time that matters is the controller's own, and it is only used against the window.

Consequence: the single-cell and scale-2 guides do not depend on any of this; the multi-cell guide
([superviseur.md](superviseur.md), step 5) describes the library and its fail-closed behaviour, not a running
service.

## Target: who holds what, who may touch it

| Item | Held by | Written by | Read by |
|---|---|---|---|
| Bundle bytes (the signed policy) | **Bundle store**: content-addressed (key = hash), read-only for cells | the build/signing machine only | cells (to load), the promotion controller (to verify) |
| Bundle signature key | HSM, m-of-n | — | verifiers (public key pinned) |
| **Epoch anchor**: (epoch, `policy_id`, healthy window `[start, end]`) | the **master chain**, as a signed record whose hash is in a `KindAnchor` leaf | the controllers' k-of-n quorum (they *define* the window; nobody measures it) | the promotion controller, supervisors |
| Pending challenges | the promotion controller, in memory | the controller | the controller |
| Promotion verdict (`KindPromotion` leaf) | the controller's own registry | the controller | the supervisor |

Principles that follow from §7.4 and the rest of the doctrine:

- **The anchor is public by design** (a hash and two times), published in the clear in a signed record; only
  the *leaf* that points to it is hash-only. A reader must be able to recover the values — a salted hash
  alone does not allow it.
- **The window is defined, never measured by the canary.** A candidate's clock or health report is never an
  input.
- **The controller is read-only toward the master** and write-only toward its own registry. A partition from
  the master is a refusal (already the behaviour).
- **No component outside the build machine writes the bundle store.**

## Candidate start-up sequence

1. Measured boot and provisioning witness ([cellule.md](cellule.md)) — unchanged.
2. Read the **epoch anchor** for the current epoch through the supervisor's read-only API; verify its
   signature against the pinned controllers.
3. Fetch the bundle **by the anchored hash** from the bundle store; verify the hash and the bundle signature;
   start OPA with that revision pinned (#92, #106). A bundle that does not match the anchor never starts.
4. Ask the promotion controller for admission (below).
5. Until admitted the cell serves nothing as a mirror; it stays what it was (canary / standby).

## Admission: challenge–response (replaces `ReceivedAt`)

1. The candidate announces itself: cell id, epoch.
2. The controller issues a **challenge**: a random nonce bound to (cell, epoch), single-use, with an expiry
   **measured on the controller's clock**. Pending challenges are bounded (saturation refuses, never evicts)
   and rate-limited per cell; a restart loses them — the candidate simply asks again.
3. The candidate answers with a signed receipt containing (cell, epoch, bundle hash, **nonce**) — and, if the
   controller holds the bundle (below), a possession proof `SHA-256(nonce ‖ bundle)`.
4. The controller checks the signature, the nonce (unconsumed, unexpired), the hash against the anchor, the
   window against its own clock, then consumes the nonce **before** writing the admission leaf (same order as
   the class-W proofs, #206). Any failure writes a refusal leaf and requires a **new request**, hence a new
   challenge.

What this fixes: freshness is proven by the controller (an old receipt cannot contain a nonce that did not
exist), replay is impossible, and no clock comparison between cells is needed. `ReceivedAt` disappears: the
signed receipt format changes, and the §7.4 text of the spec changes with it (EN and FR).

## Possession of the bundle: the open design point

Today the candidate signs a hash it may know without having received the bundle. To prove *possession*, the
verifier needs something to compare to. Two ways, to choose at the first deployment:

- **The controller holds a copy of the bundle**, fetched from the store by the anchored hash and verified.
  Simple; needs the policy not to be confidential from the controller (it is a signed artifact the cells
  load, so usually fine).
- **Anchor a Merkle root of the bundle's chunks** and have the candidate return a random chunk with its path.
  Needs no copy, but changes what `policy_id` is (it is the rules hash used everywhere): a protocol change,
  not recommended unless confidentiality forces it.

Whichever it is, the **exact bytes** hashed by `policy_id` must be defined once (today: a hash of the Rego
sources, not of the `tar.gz` that circulates).

## Decisions left for the first multi-cell deployment

1. Where the promotion controller runs (on the independent supervisor is the natural place: it already reads
   the master and writes only its own registry).
2. The publication format of the epoch anchor and who signs it (the controllers' quorum).
3. The exact bundle bytes behind `policy_id`, and which possession option above.
4. Which authority defines the healthy window, and how often.
5. Rate limits and the size of the pending-challenge set.
6. Behaviour when the master is unreachable at boot (today: refuse — keep it, and say how an operator
   recovers).

Until then: the library stays as it is, nothing claims more than it does, and R-15 stays open under #233.
