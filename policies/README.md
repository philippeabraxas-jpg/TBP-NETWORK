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

## Rule packs — named, tested, composable

A **rule pack** is a Rego package under `policies/rego/` that exports a small
API (`ok`, `violation`, `reasons`) and that a policy composes as a **guard**
(`allow if { …; hardening.ok }`), so no allow rule can bypass it. Packs are
configured **only** through the bundle's data document (signed with the bundle,
§12) — never by a value the agent supplies, and never by editing the pack.
Tests live in `policies/tests/` (outside the bundle and outside the determinism
validator) and run in CI: `opa test policies/rego policies/tests`.

### `tbp.pack.agent_hardening` — `policies/rego/pack_agent_hardening.rego`

| Check | Violation code | Rule |
|---|---|---|
| Agent identity / memory files (`SOUL.md`, `MEMORY.md`, `AGENTS.md`) | `protected-agent-file` | any write/delete needs **class W** (approved plan + quorum) — reads stay free |
| Credential stores (`.env*`, SSH/GPG/AWS/kube/docker dirs, private keys, wallets, browser data, `/etc/shadow`) | `credential-store` | denied for **every** action and class, reads included |
| Network egress | `egress-not-allowlisted`, `malformed-authority`, `opaque-uri` | a URL resource must target an allowed host; default-deny |
| Command execution (`exec`, `run`, `shell`, `execute`, `spawn`) | `command-not-allowlisted`, `shell-metacharacter` | first word must be allowlisted **exactly**; no shell metacharacters; default-deny |
| Explicit paths, never broad globs | `glob-in-resource` | a `*` in a resource is refused |
| Malformed input | `resource-invalid`, `action-invalid`, `malformed-resource` | absent, non-string, empty, invalid or double `%`-encoding is a violation — never a silently undefined rule |

Bundle data (all optional; lists **extend** the defaults, they never replace them):

```json
{
  "tbp": {
    "hardening": {
      "extra_protected_files": ["CLAUDE.md"],
      "extra_credential_files": ["secrets.yaml"],
      "extra_credential_dirs": ["vault"],
      "allowed_domains": ["api.example.org", "*.cdn.example.net"],
      "allowed_commands": ["ls", "/usr/bin/git"],
      "extra_command_actions": ["invoke"],
      "exempt_resources": ["public/server.pem"]
    }
  }
}
```

Put this in a `data.json` **next to your own policy, outside `policies/rego/`**:
anything with a `.json` extension inside `policies/rego/` is loaded into the
bundle as data, including in the deployment selftest.

**Before enabling in a deployment:**

- **Egress is default-deny.** If your resources are URLs, list the hosts in
  `allowed_domains` first, or every URL action is refused. `*.example.net`
  covers subdomains only, not `example.net` itself.
- **Commands are default-deny.** With no `allowed_commands`, no command action
  passes. `ls` allows `ls …` and nothing else (not `/tmp/ls`, not `lsof`).
- **The pack judges the canonical form** of the resource (§4.5). It normalises
  case, `%`-encoding, `\`, `..`, trailing dots/spaces and `:stream` suffixes,
  but does not resolve symlinks, 8.3 short names or filesystem aliases, and a
  scheme-less string that merely looks like a host (`evil.example/x`) is not
  recognised as a URL. Canonicalisation and containment of the executor are the
  translator's and the integrator's job (see #180).
- **`exempt_resources` is an exception, not a fix.** It is exact-match, comes
  from the signed bundle, and should be reviewed like any other policy change.

