# FreeRADIUS — 802.1X / EAP-TLS (spec §5.1)

The NAC is a **switchboard**, not a wall: authenticated (802.1X, EAP-TLS)
→ VLAN granting access to the broker; unknown → **captive VLAN** whose
only route is enrollment or the forced-broker path. **EAP-TLS must reuse
the same PKI as the TBP handshake (§3)** — a single identity
infrastructure, not two.

## What's still missing here

No FreeRADIUS config is provided yet — this folder is an anchor point,
not a ready-to-deploy setup. To produce before pilot P1 (§13):

- `clients.conf`: declaring switches/APs as RADIUS clients (shared
  secrets — never committed, see the root `.gitignore`).
- `sites-available/tbp-eap-tls`: dedicated EAP-TLS site, certificates
  issued by the same authority as the handshake (§3), a private CA
  dedicated to the pilot, never FreeRADIUS's default test CA.
- `mods-available/eap`: force `tls-config` onto the pilot's CA, disable
  EAP methods other than TLS (no PEAP/MSCHAPv2 in parallel — a single
  authentication path, consistent with the "never by name, always by
  signature" doctrine, §1).

## Critical configuration points (doctrine §5.3)

- **Fail-closed is mandatory**: FreeRADIUS's default behavior on a reject
  or timeout is to refuse — **never** configure an "open" fallback VLAN on
  authentication failure. The reference text calls this "RADIUS's often
  implicit fail-open default": it must be forced fail-closed **at the
  switch level** (default VLAN assignment = captive VLAN, never a trusted
  VLAN), not only on the RADIUS server side.
- **MAB (MAC Authentication Bypass)**: if used for IoT devices that don't
  support 802.1X, it must remain an **instrumented channel** (§5.3) —
  dedicated IoT VLAN, never silent, telemetry feeding the registry like
  any other "hole" in the wall.
- **Progressive rollout**: `monitor` mode (auth logged, not yet enforced)
  before `closed` (VLAN actually constrained) — never the reverse in
  production. No RADIUS-assigned VLAN in v1 (`tunnel-private-group-id`
  disabled initially) — the NAC only routes authenticated/unauthenticated
  at first; per-profile VLAN granularity comes after the pilot is
  validated.

## OCSP/CRL verification

An unreachable OCSP or CRL must **never** be a silent soft-fail (cert
accepted by default) — route to a remediation VLAN with visible feedback
to the user, never a silent block nor a silent pass-through.
