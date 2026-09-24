# FreeRADIUS — 802.1X / EAP-TLS (spec §5.1)

The NAC is a **switchboard**, not a wall: authenticated (802.1X, EAP-TLS)
→ VLAN granting access to the broker; unknown → **captive VLAN** whose
only route is enrollment or the forced-broker path. **EAP-TLS must reuse
the same PKI as the TBP handshake (§3)** — a single identity
infrastructure, not two.

## What's delivered here (issue #130)

This folder is no longer just an anchor point: `scripts/render_config.sh`
turns a STOCK FreeRADIUS install (the real package, any version — never a
hand-duplicated copy of its config, which would drift) into a deployable
EAP-TLS configuration on the pilot's PKI, and `clients.conf.example` is a
real starting template for declaring switches/APs. Adapt, never copy
as-is (D99):

```sh
# 1. Bootstrap the pilot CA (or point at a real, HSM-backed one in prod —
#    see scripts/README.md).
sh scripts/ca_dev.sh

# 2. Render the real FreeRADIUS config from the installed package —
#    EAP-TLS only, this CA, OCSP live-checked (see below).
sh scripts/render_config.sh /etc/freeradius/3.0 /etc/freeradius/3.0 \
    certs/dev "http://<ocsp-host>:8888/"

# 3. Adapt clients.conf (secrets per switch — never committed) and the
#    switch-side VLAN policy (T20) — these stay specific to each
#    deployment, never generated here.
install -m 0640 clients.conf.example /etc/freeradius/3.0/clients.conf
# … edit secrets, then:
freeradius -XC   # configuration check before ever starting the service

# 4. Start the OCSP responder (dev) BEFORE FreeRADIUS, or point at a
#    real production responder — see "Revocation without a restart" below.
sh scripts/ocsp_responder.sh start
```

`sites-available/tbp-eap-tls` is intentionally not shipped as a separate
file: FreeRADIUS's stock `sites-available/default` already implements
EAP-TLS admission once `render_config.sh` has forced TLS-only in the eap
module — a dedicated site would duplicate it for no behavioral gain.
Restricting the site itself (dropping non-EAP auth methods it doesn't
need) is a T20 hardening step, tracked separately from this issue's two
bugs.

## Revocation without a restart (issue #130)

Before this fix, a revoked certificate was only rejected once FreeRADIUS
itself restarted (the CRL is loaded once, at startup) — a real gap: a
freshly revoked endpoint kept re-authenticating successfully until an
operator happened to restart the service. Two mechanisms now close it,
without ever restarting FreeRADIUS itself:

- **OCSP, checked live on every EAP-TLS handshake** (`render_config.sh`
  enables `ocsp { enable = yes }` in the eap module, pointed at
  `ocsp_responder.sh`). `revoke_client.sh` now reloads this responder
  automatically after every revocation — reloading a small, stateless
  helper process (well under a second) is not the same as restarting the
  RADIUS service: FreeRADIUS keeps serving every other client throughout.
  The CRL is still regenerated on every revocation too (defense in depth
  for when OCSP is unreachable, §5.3: never a silent soft-fail there —
  route to remediation).
- **RADIUS CoA/Disconnect-Request** (`disconnect_client.sh`, RFC 5176),
  best-effort: terminates a session that was already established *before*
  the revocation. Requires a NAS with CoA enabled (T19/T20) — optional,
  silently a no-op if `TBP_NAC_COA_NAS` is not configured.

`scripts/test_eap_tls.sh` proves the OCSP path end to end against a real
FreeRADIUS process: revoke, then re-authenticate with the same
already-running server (its PID checked unchanged) and observe the
Access-Reject.

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
