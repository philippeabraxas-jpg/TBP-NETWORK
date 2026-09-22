# Acceptance checklist — router (T35, issue #61)

_Version française : [routeur.fr.md](routeur.fr.md)._

To be checked on the machine, in order. One red box = STOP.

## §5.1 Segmentation

- [ ] The six VLANs exist and are `UP` (10 server, 20 auth, 33 IoT/MAB,
      66 captive, 77 remediation, 99 mgmt — plan to adapt to the pilot).
- [ ] `nft list table inet tbp_p1` shows the walls and their counters
      (reference file `config/nftables/router-p1.nft`, to adapt).
- [ ] The counters move when traffic crosses (visibility before
      filtering — same doctrine as monitor before closed, §5.3).

## §3/§12 Authentication

- [ ] EAP-TLS only (no PEAP/MSCHAP), pilot PKI (§3).
- [ ] `freeradius -XC` green; RADIUS listens only on the auth VLAN.
- [ ] No certificate/key is committed (`config/freeradius/certs/` is
      gitignored; the PKI is generated for THIS deployment).

## Fail-closed at the switch

- [ ] Default VLAN = captive (66): an unknown device is NEVER admitted.
- [ ] Revoked certificate or unreachable OCSP/CRL = remediation (77),
      observed with a revoked test certificate.
- [ ] All three outcomes (admitted → 10, unknown → 66, revoked → 77) have been
      OBSERVED in the lab, not assumed (router-debian.md step 7).

## MAB (devices without an 802.1X supplicant)

- [ ] MAB is confined to the dedicated IoT VLAN (33) — never on a trusted
      VLAN.
- [ ] Every MAB admission is logged and counted: a MAB device
      **never silent** — instrumented channel, not a backdoor.
- [ ] An unknown MAB device falls to captive like any unknown.
