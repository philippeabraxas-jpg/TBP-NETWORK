# OWASP API Security Top 10 (2023)

**Status: Full**
**Source**: [issue #162](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/162) · fix: [issue #163 / PR #164](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/163)
**Reference**: OWASP API Security Top 10, 2023 edition (still current).
**Last verified**: 2026-09-29

## Scope note

Last of the four frameworks added after the initial series closed. Unlike most frameworks catalogued earlier, this one applies DIRECTLY to the code's real HTTP endpoints — `POST /v1/actions` (data plane, `server.go`), `GET /v1/supervision/*` (admin plane, #95), the supervision console (#86).

Legend: ✅ Covered · 🔴 Real gap (needs code; the row links the issue that tracks it) · ⚪ Not TBP's concern (the row says why and, for a deployment, how to close it). A combined status splits one control between what TBP covers and what stays with the deployer. See the [catalogue README](README.md).

## The 10 risks vs. `POST /v1/actions`

| # | Risk | Status | Detail |
|---|---|---|---|
| **API1** | Broken Object Level Authorization (BOLA) | ✅ | **Fixed** — see below. |
| **API2** | Broken Authentication | ✅ · ⚪ certificate profile | **Fixed** — see below. **Identity is the certificate CN only** (bound to the subject's `transport_identity`; an agent bound to a certificate is refused on the Unix socket, `agent-network-only`, so a local process cannot speak as it); Go's TLS stack already requires the `clientAuth` extended key usage, but SAN and other profile fields are not checked. **Why grey:** the certificate profile is the deployer's PKI policy. **To close:** use a CA dedicated to agent client certificates (never one shared with the NAC or other services) as `TBP_BROKER_TLS_CLIENT_CA_FILE`, and issue short-lived certificates with EKU `clientAuth` only and CN = the agent's subject — see `deploy/cellule.md` step 7. |
| **API3** | Broken Object Property Level Authorization (mass assignment) | ✅ | `dec.DisallowUnknownFields()` (`server.go:handleAction`) categorically rejects any unexpected JSON field — direct mass-assignment protection. |
| **API4** | Unrestricted Resource Consumption | ✅ | `defaultMaxBody` (64 KiB), `maxIntentBytes`, `maxIssSubActionLen`, and the `AgentQuotaPolicy` cap (#125) resolved by the broker — solid coverage, same finding as LLM06 ([#143](143-owasp-llm-top10.md)). Since [#209](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/209), every HTTP listener of `pepd` and `brokerd` has read, header and idle timeouts (5 s / 10 s / 60 s — a stalled client is cut at 10 s, not held forever) and a bounded body read before the JSON decode (16 KiB on evaluation, 64 KiB on admin routes, `413` above); the transparent proxy keeps no read deadline on purpose (it relays the agent's own long requests). Exercised end to end in `deploy/selftest` (two `413`, one cut stalled client). |
| **API5** | Broken Function Level Authorization | ✅ | Data/admin plane separation (§95): two distinct HTTP muxes, two distinct sockets, `POST` on a supervision view → 405. A clean example of strict functional separation. |
| **API6** | Unrestricted Access to Sensitive Business Flows | ✅ agents registered W · ⚪ class of the action (refused, #195) | `QuorumGate` (class W) limits access to a sensitive business flow (an irreversible action) to a k-of-n approval, for agents registered class W. The class is the agent's, not the action's: see [#195](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/195). **To close (deployment):** register every agent that can perform such a flow as class W. |
| **API7** | Server-Side Request Forgery (SSRF) | ✅ | TBP NEVER makes an outbound request built from caller-supplied data — the OPA/envelope endpoints are FIXED configuration URLs, never derived from `resource`. No SSRF surface by construction. |
| **API8** | Security Misconfiguration | ✅ | The devmode-sentinel doctrine (#113) + generalized configuration fail-closed make a misconfiguration block startup rather than silently become exploitable; error responses carry stable `Reason` codes, never raw Go stack traces. |
| **API9** | Improper Inventory Management | ✅ | Routes are explicit, one registration per route, all under `/v1/`, with a single version and no deprecated route. Inventory (kept in step with the code — a new route is a new row): **brokerd data plane** (Unix socket or mTLS) `POST /v1/actions`; **brokerd admin plane** (Unix socket) `GET /v1/supervision/{stats,epoch,arbitration}`, `POST /v1/supervision/plan/{submit,approve}`, `POST /v1/epoch/renew`; **pepd data plane** (TCP) `/v1/evaluate`, `/v1/passport/consume`; **pepd admin plane** (Unix socket) `/v1/mode`, `/healthz`; **supervisord console** `GET /v1/{arbitration,epoch,indicators}`; **anod** (Unix socket, no network) `POST /v1/{mask,mask-query,unmask,close}`, `GET /healthz`. |
| **API10** | Unsafe Consumption of APIs | ✅ | The OPA client (`pep.OPAClient`) already treats a third party's (OPA's) response as potentially faulty — timeout, 5ms circuit breaker, fail-closed deny on any malformed response (T11). |

## API1/API2 in detail — the real gap this catalog found, now fixed

**Finding**: `POST /v1/actions` authenticated the CONNECTION (mandatory mTLS since #124, or `SO_PEERCRED` on the Unix socket), and `AgentRegistry` (#125) resolved class/quota from the `subject` declared in the request's JSON body — but nothing verified that the transport-authenticated peer was actually authorized to act ON BEHALF OF that specific `subject`. Two agents sharing socket access (same Unix group, or a reused mTLS client certificate in some deployments) could declare ANY registered `subject` and consume its class/quota. Exactly the BOLA/Broken Authentication risk class: authentication exists, but it doesn't BIND the authenticated identity to the object (here: agent identity) the action targets.

**Fix** (#163, PR #164): `AgentRecord.TransportIdentity` + verification of the mTLS client certificate's CN before any class/quota resolution (`agent-transport-unbound` refusal on mismatch). The declared `subject` is never again accepted on its word alone — it must exactly match the transport fact verified by the TLS stack (never re-read from the request body).

**Non-vacuous proof**: `TestBrokerdNetworkSubjectBoundToTransportIdentity` proves all three cases — valid certificate + matching subject → allow; matching subject with no registered `transport_identity` → deny; valid certificate but a DIFFERENT agent's subject → deny (the exact impersonation vector this catalog described).

**Nuance kept**: the Unix socket retains its coarser-grained boundary (0660 permissions, §7.1) — a documented choice, not an oversight (see #163/PR #164).

---

## Summary

**This catalog found a real, previously unnamed gap on code already in production** (#124/#125 both merged) — treated with more urgency than the recurring `SkillRegistry` gap, since it touched the live token-issuance path rather than a not-yet-built feature. Now fixed.

**Rest of the catalog strongly positive**: 5 of 10 risks direct ✅ even before the fix, now all 10 ✅ (API6 qualified: the quorum applies to agents registered class W, [#195](https://github.com/philippeabraxas-jpg/TBP-NETWORK/issues/195)) — consistent with the rest of the series: TBP is strong on strict input validation and functional separation.
