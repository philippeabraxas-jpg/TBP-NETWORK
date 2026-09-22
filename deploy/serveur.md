# deploy/serveur.md — "server" machine (T35, issue #61)

_Version française : [serveur.fr.md](serveur.fr.md)._

The server hosts the application (PostgreSQL, business service…). Its
doctrine: **acceptance via ITS cell's broker only** — the
server trusts neither the network, nor another PEP, nor itself.
The PEP `pepd` runs here (or on the cell depending on the chosen
partitioning); the instructions below assume pepd on the server.

#### Step 1 — Machine prerequisites

**Verifiable prerequisite**: common steps of [README.md](README.md)
green; the attachment cell is installed
([cellule.md](cellule.md)) and in monitor; the custody matrix (D97)
is respected — no governance key transits through this server.

**Command**:

```bash
go version
getent hosts cell-a   # or IP: reachability of the attachment cell
```

**Observable success criterion**: go ≥ 1.24; the cell answers at the
expected name or IP.

**On failure: STOP** — no reachable cell, no useful PEP;
finish the cell first.

#### Step 2 — Install and start pepd (monitor, §5.3)

**Verifiable prerequisite**: step 1 green; keyring, policy ID and salt
prepared PER cellule.md steps 4-6 (local salt ≥ 16 bytes, never
shared; `/etc/tbp/pepd.env` at 0600).

**Command**:

```bash
go build -o /usr/local/bin/pepd ./src/pep/cmd/pepd
set -a; . /etc/tbp/pepd.env; set +a
/usr/local/bin/pepd &
curl -s http://127.0.0.1:8443/v1/mode
```

**Observable success criterion**: `{"mode":"monitor"}`; `/healthz` 200;
tessera registry initialized in `TBP_REGISTRY_DIR` (local cell
key, 0600).

**On failure: STOP** — any missing environment (`TBP_SALT`,
`TBP_KEYRING_FILE`, `TBP_POLICY_ID`) MUST make startup fail; a
pepd that starts incomplete is a fake pepd.

#### Step 3 — Wire the application to the PEP (broker-only acceptance)

**Verifiable prerequisite**: step 2 green.

**Command**:

```bash
# PostgreSQL: the extension applies both §4.4(3) hooks —
# structural (post_parse_analyze) + frozen-plan seal (ExecutorStart):
ls src/pep/postgres-extension/
# The business app calls POST /v1/evaluate BEFORE executing, and
# POST /v1/consume at execution time (quota passport §4.1-bis).
curl -s -X POST http://127.0.0.1:8443/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"token":"<cwt base64>","action":"read","resource":"doc-1","epoch":0}'
```

**Observable success criterion**: the JSON verdict returns `allow`, `mode`
(monitor), `forwarded`; in monitor, even a deny is `forwarded=true`
(log only) with an explicit `reason` — the selftest's mono phase
witness shows `opa-deny`.

**On failure: STOP** — an unreadable verdict or a non-200 HTTP is
not a usable deny; fix the chain before going further.

#### Step 4 — Host hardening

**Verifiable prerequisite**: steps 2-3 green.

**Command**:

```bash
# Starting point to adapt to the local kernel (D99) — never copied as-is:
less config/sysctl/99-tbp-hardening.conf   # to adapt before applying
# Hardened unit pattern (T24) to adapt for pepd.service:
less src/translator/tbp-translator.service
```

**Observable success criterion**: the pepd unit is in place with
cap-drop, seccomp `@system-service`, `ProtectSystem=strict`,
`EnvironmentFile` at 0600; `audit_confinement.sh` (T24 pattern, to adapt)
reports no drift.

**On failure: STOP** — an unconfined PEP is an attack surface; fix
the unit before opening the service to applications.

#### Step 5 — §9.1 measurements in monitor, then switch request

**Verifiable prerequisite**: steps 2-4 green; agreed monitor observation
window elapsed; the supervisor collects the leaves
(deploy/superviseur.md).

**Command**:

```bash
# Counters exposed by the listener (GET /v1/stats if wired, otherwise
# registry): forwarded, would-deny, denied, latencies. Executable
# reference for the measurement points: tests/p1_friction/ (T27).
curl -s http://127.0.0.1:8443/healthz
```

**Observable success criterion**: the §9.1 measurement points are
installed AND fed in monitor — this is a prerequisite of
[monitor-to-closed.md](monitor-to-closed.md) (D100), not an option.

**On failure: STOP** — no measurement, no closed request. The
switch is decided by quorum (§5.3), never locally on this server.

## What this server NEVER does

- accept a token without going through its cell's PEP/broker;
- host a controller key, another cell's salt, or a
  capabilities.json copied from another deployment (it is regenerated from
  THE deployed OPA — see cellule.md step 3, and config/ remains to adapt);
- switch itself to closed: `POST /v1/mode` requires the quorum (403
  otherwise — demonstrated by the selftest's mono phase).
