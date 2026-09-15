# Policies — OPA / Rego (spec §12 checklist)

## `capabilities.json` — generate it, don't copy one

No `capabilities.json` is provided in this folder: its real content
depends on the actually-deployed OPA version (the built-in list changes
between versions), so a hand-written file here would be either wrong or
obsolete as soon as OPA is upgraded — a worse security risk than having no
file at all (believing `http.send` is blocked when it no longer is).

Correct sequence, to document in the deployment pipeline:

```sh
# 1. Generate the full built-in list of THE deployed OPA version
opa capabilities > policies/capabilities.json

# 2. Manually remove built-ins that violate the doctrine (spec §12):
#    - http.send            (no outbound network call from a rule)
#    - net.lookup_ip_addr   (same reason)
#    - time.now_ns          (time comes from the broker/NTS, not OPA's local clock — §6.2)
#    - opa.runtime          (unless a use is already audited and justified,
#                            e.g. reading an environment token — never for I/O)

# 3. Start OPA with this restricted capabilities file:
opa run --server --capabilities policies/capabilities.json ...
```

**OPA circuit-breaker (mentioned §0/§12)**: this is not a native OPA
mechanism — nothing built into the Rego engine cuts off an evaluation at
5 ms. It's a property to implement on the caller side (the PEP/broker,
see `src/pep/`): a strict timeout on the call to OPA, **fail-closed**
(deny) if exceeded. Do not present this as a guarantee OPA itself
provides, in documentation or code — same principle as the honest prefix
already established elsewhere in the TBP ecosystem to never imply a check
that doesn't exist.

## `rego/` — policy examples

See [`rego/README.md`](./rego/) for starter skeletons (default-deny,
minimal structure consistent with doctrine §1). These are **illustrative
examples** to bootstrap the pilot's own rules (§14: "règles propres" /
"own rules"), not a reference policy to deploy as-is.
