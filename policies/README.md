# Policies — OPA / Rego (spec §12 checklist)

## `capabilities.json` — generate it, don't copy one

No `capabilities.json` is provided in this folder: its real content
depends on the actually-deployed OPA version (the built-in list changes
between versions), so a hand-written file here would be either wrong or
obsolete as soon as OPA is upgraded — a worse security risk than having no
file at all (believing `http.send` is blocked when it no longer is).

Correct sequence, to document in the deployment pipeline:

```sh
# 1. Generate the full built-in list of THE deployed OPA version.
#    Without --current, 'opa capabilities' prints version NAMES (text);
#    the JSON document of this version requires --current.
opa capabilities --current > policies/capabilities.json

# 2. Manually remove built-ins that violate the doctrine (spec §12):
#    - http.send            (no outbound network call from a rule)
#    - net.lookup_ip_addr   (same reason)
#    - time.now_ns          (time comes from the broker/NTS, not OPA's local clock — §6.2)
#    - opa.runtime          (unless a use is already audited and justified,
#                            e.g. reading an environment token — never for I/O)
#    Keep every other top-level key of the document (features, future_keywords,
#    wasm_abi_versions) untouched — dropping 'features' breaks rego_v1 parsing.

# 3. OPA ≥ 1.0: 'opa run' no longer has a --capabilities flag. Compile a
#    bundle WITH the restricted file (forbidden built-ins are rejected at
#    build time), then run the bundle:
opa build --capabilities policies/capabilities.json policies/rego/ -o bundle.tar.gz
opa run --server bundle.tar.gz
```

(The full recipe — presence-before-strip assertion, negative check with
`policies/testdata/rule_http_send.rego` — is automated by
`policies/gen_capabilities.sh` and executed for real by the deployment
selftest, `deploy/selftest/`.)

**Bundle signing (security review #106)**: the snippet above is
illustrative only — a bundle's `--revision` is a self-declared label,
never a proof that the content wasn't altered after it was built.
Production builds MUST also sign the bundle (`opa build --signing-key
…`) and OPA MUST verify it at load (`opa run --bundle … --verification-key
…`, NOT a bare positional bundle path — verification only activates in
`--bundle` mode). See `deploy/cellule.md` step 4/5 for the full command
and key-custody doctrine.

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
