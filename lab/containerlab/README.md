# L2/L3 test topology (containerlab)

Nothing defined yet. Goal per the spec: emulate the pilot P1 topology
(§13) — 1 server VLAN, Debian router, 2 cells, 802.1X NAC — without
physical hardware, to test `config/nftables/`, `config/freeradius/`, and
fail-closed behavior (§5.3) before any real deployment.

To define before writing a `.clab.yml` file:
- Nodes: how many simulated "endpoints," a switch (or an image emulating
  one, e.g. `ceos`/`cvx` depending on availability), the Debian router
  with the configs from `config/`.
- Minimal scenario to validate first: an 802.1X-authenticated endpoint
  reaches the broker; an unregistered endpoint lands in the captive VLAN
  — the most basic test of the "wall and switchboard" (§5.1).
