# deploy/integration-contract.md — what an integrator must know (issue #210)

_Version française : [integration-contract.fr.md](integration-contract.fr.md)._

Limits and obligations that the code cannot enforce for you, found by the red-team review
tracked in #210 and written down here so that nobody discovers them in production. None of
them is a defect to fix in TBP: each is either a contract the integration must honour, a
bound to size against, or a design choice with a cost.

## 1. The object seal is only worth what the service recomputes (R-4)

The object-capability seal (claim −5, §4.4(2)) binds an authorisation to the **exact
business object** it was issued for: a token that carries a seal authorises only the body or
state that hashes to it (`ReasonSealMismatch` otherwise).

Whether that holds depends on **who computes the seal**:

| Path | Who computes the seal | Holds? |
|---|---|---|
| Transparent proxy (`pepd` in front of an HTTP backend) | `pepd` itself: SHA-256 of the body it relays (#108) | **Yes** — the agent chooses nothing |
| `POST /v1/evaluate`, and `brokerd` structured mode (`object_seal` in the intent) | **The presenter** (the agent supplies `object_seal`; the issuer copies it into the token; the validator compares the token's seal with the request's) | **Only if the service recomputes it** |

On the second path both values are chosen by the presenter, so they are equal by
construction: the check proves nothing about the real object. The capability is real only when
the **service that executes the action recomputes `ComputeObjectSeal`
(`src/pep/object_capability.go`) over the actual state and compares it with the token's
claim −5** (or submits its own recomputed seal to `evaluate`), as the PostgreSQL integration
does server-side. This is therefore a **mandatory integration contract**:

- If your service executes an action on a business object and relies on the seal, it recomputes
  the seal from the real object at execution time. A seal received from the agent is never
  trusted by itself.
- If it cannot recompute (a generic HTTP service with no adapter), do not count the seal as a
  control: rely on the proxy path, on OPA rules over `resource`, and on the executor's own
  confinement ([execution-sandbox.md](execution-sandbox.md)).

## 2. Bounds compose; they do not add up (R-1, R-5)

Each bound is individually sensible; their composition is smaller than any of them:

- **Intent: 4096 bytes of JSON.** `quorum_proof` (≤ 4096 raw bytes) and `plan_binding`
  (≤ 4135 raw bytes) travel **hex-encoded inside that intent**, which doubles them. A proof or
  binding cannot use its own maximum: past roughly 2 KiB raw — a few co-signers' worth of class W
  quorum — the request is refused (`request-invalid`) and the operator sees an opaque refusal.
  Size your quorum (k and signature encoding) against that, not against 4096.
- **Token: 1024 bytes on the wire.** The token carries subject, action, cell id, `resource`
  (≤ 1024) and, with a passport, `quota.resource` (≤ 1024) too. A legitimate composition can
  exceed the wire cap well before either field reaches its own maximum (the red-team estimate:
  `resource` ≳ 600 bytes with a passport); the issuer then refuses with `ErrTokenTooLarge`.
  It is fail-closed, but it is a functional denial of service for legitimate requests: keep
  resource identifiers short (identifiers, not paths or queries), and put what is long in the
  action's parameters, bound by `plan_binding`.

## 3. Friction notes (R-6, R-2)

- **The action class is per agent, not per request (R-6).** The registry resolves one class for
  an agent (#125); an agent that mixes reads and infrastructure writes is held to the strictest
  tier, plan binding included, on **all** its requests. That is deliberate (the class is never
  taken from the agent). The way out is operational: register distinct agents per activity, or
  refine in Rego with `SkillInput` (see the `risk_tier` pack). Counted as friction (§9.1).
- **`quota.resource` is not the action's `resource` (R-2).** The passport's resource (what is
  counted) and the action's resource (what is touched) are separate on purpose — the data plane
  is not the API route. What ties them is the OPA envelope rule and the registry's cap. Policy
  authors should write the rule that matches them if they want them equal.

## 4. What peer credentials do and do not do (R-20)

`SO_PEERCRED` on the OPA socket checks the **UID** of the peer at each connection. An attacker
who already runs as the same UID can kill OPA and bind the socket again: the check **delays** an
impersonation, it does not prevent it. Run OPA under its own account, with the socket mode and
directory ownership set so that only `pepd` and OPA share it (see [cellule.md](cellule.md)), and
count on measured boot (#112) and the provisioning witness (#192) for what an attacker with that
account could change.
