# deploy/network-isolation.md — proving that no route out exists except through TBP (issue #186)

_Version française : [network-isolation.fr.md](network-isolation.fr.md)._

"An agent cannot bypass TBP to reach the outside" is **not a property of TBP's code**. It is a
property of the **deployment**: a VLAN dedicated to the cell, and firewall rules that force every
outbound flow through the PEP's blocking proxy (`src/pep/proxy.go`, #94). TBP never claims that
this is closed — `config/nftables/pep-redirect.nft` is a skeleton whose real rule is commented out
("do not deploy as is"). An AI will take the route outside TBP if it exists, so the guarantee cannot
rest on a configuration *assumed* correct. It is tested, actively, at every deployment:

```bash
deploy/verify_network_isolation.sh --allow 10.20.0.5:8081 --mode report   # calibration
deploy/verify_network_isolation.sh --allow 10.20.0.5:8081 --mode strict   # deployment gate
```

`--allow` is the PEP's blocking-proxy address (`TBP_PROXY_ADDR`), the **only** destination the agent
may reach.

## What it checks

1. **Positive control.** The allowed destination must be *reachable* from the agent's context.
   Without it, "everything fails" proves nothing (network down, wrong context, proxy stopped) — the
   script then exits `2`, never "compliant".
2. **Negative probes.** TCP connections to arbitrary destinations — internet IPs (v4 and v6) and a
   DNS name — must **all fail**. A connection that succeeds is a route out: a violation.
3. **Rules actually loaded.** The kernel has the expected nftables table with at least one *active*
   rule that drops or redirects (a commented-out line, as in the skeleton, does not count; neither
   does a `.nft` file sitting on disk).

## Where to run it

From **the agent's network context** — that is the context under test:

| Situation | Option |
|---|---|
| The agent runs in a network namespace | `--netns NAME` |
| The agent is a container or a systemd unit | `--pid <main pid>` |
| Rules are keyed on the agent's UID (`meta skuid`) | `--as-user AGENTUSER` |
| You are already in the agent's context | no option |

Reading the kernel rules needs `root` (or `CAP_NET_ADMIN`); run the script as root and select the
agent context with the options above, or use `--no-nft` and accept that point 3 is not checked.

## Modes — monitor before closed (§5.3)

- `--mode report` (default): prints everything, exits `0` even with violations. For calibrating a new
  deployment, when the rules are not final yet.
- `--mode strict`: any violation exits `1`; unreadable rules exit `2` (it will not conclude without
  looking). Wire this as the **deployment gate**, and re-run it after any change of network rules.

Exit codes are those of `src/translator/audit_confinement.sh`: `0` compliant, `1` violation, `2` usage
or environment error.

## What it does not prove

State it plainly, so the report is not read as a guarantee:

- Only **TCP** is probed. UDP, ICMP and covert channels (DNS tunnelling, an allowed host that relays)
  are not.
- A failed probe is not proof of a rule (a host may simply be down): that is why the probe list is
  varied and the positive control is mandatory. Add your own destinations with `--probe HOST:PORT`
  (your internal services the agent must **not** reach included).
- It attests the state **at the time it runs**. Run it at each deployment and on a schedule; the audit
  confinement of the translator process is a separate script (`src/translator/audit_confinement.sh`).
- It tests the agent's route to the outside, not whether the PEP's proxy is configured correctly: that
  is the proxy's own tests (`src/pep`).

## Tested

`deploy/test_verify_network_isolation.sh` (run by `deploy/selftest/selftest.sh`, so by CI) attacks the
script with real local listeners — a route out that connects, a refused port, an unreachable allowed
destination, a commented-out rule, an absent table, an unreadable `nft` — and was checked by mutation:
removing the probe, the positive control or the comment filter turns a test red.
