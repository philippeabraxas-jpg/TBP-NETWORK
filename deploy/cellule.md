# deploy/cellule.md — "cell" machine (T35, issue #61)

_Version française : [cellule.fr.md](cellule.fr.md)._

A cell runs: the **broker** `brokerd` (T37 — issue #74), the
**tessera registry** (T7), **OPA** (T11, restricted capabilities
§12), the **epoch tracker** (§7.2) and the PEP `pepd`. Every decision
leaves a leaf (§4.1); the leaf salt stays on THIS machine
(§6.2). Posture at startup: **monitor**, at the FIRST deployment only
(§5.3). Security review #93: any RESTART (the cell's registry key
already exists) starts in **refused** — everything is denied, even an
otherwise-allowed evaluation — until a quorum explicitly reconfirms a
posture via `POST /v1/mode`. A restart never silently resumes the
posture the cell had before.

> The mono phase of `deploy/selftest/` executes steps 1 to 6 of this
> guide against the real binaries, and the daemons phase executes step 7
> (real brokerd, real OPA, end-to-end action). If a command
> below diverges from the selftest, the selftest breaks: fix the guide
> or the code, never both behind each other's back.

#### Step 1 — Verify the machine prerequisites

**Verifiable prerequisite**: common steps of [README.md](README.md)
green; genesis artefacts received per the custody matrix
(`pubkeys/*.hex` of the controllers, `epoch0.json` — NEVER a controller
private key on this machine).

**Command**:

```bash
go version && opa version
ls "$GENESIS_HOME/manifest.json" "$GENESIS_HOME/pubkeys/" "$GENESIS_HOME/epoch0.json"
```

**Observable success criterion**: conforming versions; all three
genesis artefacts exist and are readable.

**On failure: STOP** — without genesis artefacts, no epoch
tracker; back to step 3 of the README.

#### Step 2 — Build the PEP (pepd)

**Verifiable prerequisite**: step 1 green; repository present on the machine.

**Command**:

```bash
go build -o /usr/local/bin/pepd ./src/pep/cmd/pepd
/usr/local/bin/pepd 2>&1 | head -1   # without TBP_SALT: must refuse
```

**Observable success criterion**: the binary builds; launched without
environment, it exits immediately with `pepd: TBP_SALT requis`
(fail-closed at startup — this refusal IS the criterion).

**On failure: STOP** — a PEP that starts without a salt is fail-open;
do not continue, fix the cause (binary, environment).

#### Step 3 — Generate the restricted OPA capabilities (§12)

**Verifiable prerequisite**: `opa` ≥ 1.0 installed (step 1).

**Command**:

```bash
bash policies/gen_capabilities.sh
# writes policies/capabilities.json (gitignored, never committed) and proves
# that a rule calling http.send is refused at load time
```

**Observable success criterion**: `vérification négative OK` displayed;
`capabilities.json` written; the forbidden built-ins (`http.send`,
`net.lookup_ip_addr`, `time.now_ns`, `opa.runtime`, and the non-deterministic
ones: `rand.intn`, `uuid.rfc4122`, `io.jwt.decode_verify`, `io.jwt.encode_sign*`,
`crypto.x509.parse_and_verify_certificates*`) are absent from it.

**On failure: STOP** — if a forbidden built-in is "absent from the
generated list", the OPA version has changed: review FORBIDDEN before any
deployment. Never hand-write capabilities.json.

#### Step 4 — Sign and build the rule bundle WITH the capabilities (OPA ≥ 1.0)

**Verifiable prerequisite**: step 3 green; the pilot's own rules
written (the skeletons in `policies/rego/` are examples to adapt,
§14 — never a reference policy to copy); `openssl` present.

**Why sign the bundle** (security review #106): `TBP_POLICY_ID` alone is
a self-declared label chosen AT build time — whoever can write
`/etc/tbp/bundle.tar.gz` can simply put the matching value in it, and
`OPARevisionWatcher` (security review #92, finding A5) would see nothing
wrong. Only a cryptographic SIGNATURE, verified by OPA itself BEFORE it
will even start serving, proves the bundle's content was not altered
after whoever built it signed it. The PRIVATE signing key never touches
a cell — same custody boundary as the quorum controllers' keys (§12):
generate it once, offline or on the machine/CI that builds bundles, keep
it there; distribute only the PUBLIC verification key to every cell and
broker, alongside `cell_log.vkey` / `keyring.json` (D97).

**Command**:

```bash
# ONCE, on the offline/build machine — NEVER on a cell. Re-run only to
# rotate the key (then every cell's policy-verify.pub must be updated
# together, or OPA on the un-updated cells will refuse every future
# bundle — a deliberate fail-closed, not a bug).
openssl genrsa -out policy-signing.key 2048
openssl rsa -in policy-signing.key -pubout -out policy-verify.pub
# policy-signing.key stays on the build machine (custody like §12
# controller keys). Copy ONLY policy-verify.pub to /etc/tbp/ on every
# cell and broker.

# TBP_POLICY_ID is chosen HERE, BEFORE the build — it becomes the bundle's
# pinned revision (security review #92, finding A5): the revision OPA
# actually serves is checked PERIODICALLY against this exact string,
# never against the built artifact's own hash (which --revision changes,
# so it cannot be computed AFTER the build without another circular
# build). Any stable identifier works (a hash of policies/rego/ sources,
# a version tag) as long as it is regenerated whenever the rules change.
POLICY_ID=$(sha256sum -- policies/rego/*.rego | sha256sum | cut -d' ' -f1)
# 'opa run' no longer has a --capabilities flag since OPA 1.0: the
# restriction is frozen at bundle compile time. -b (bundle mode) is
# REQUIRED for --signing-key to take effect at all — opa build silently
# refuses to sign without it (checked against the real opa binary).
opa build --capabilities policies/capabilities.json --revision "$POLICY_ID" \
  --signing-key policy-signing.key --signing-alg RS256 \
  -b policies/rego/ -o /etc/tbp/bundle.tar.gz
echo "$POLICY_ID"   # this value = TBP_POLICY_ID below (claim −1)
```

**Observable success criterion**: the build succeeds; a rule calling
`http.send` added as a test breaks the build (remove the test
afterwards); `tar tzf /etc/tbp/bundle.tar.gz` lists a `.signatures.json`
member.

**On failure: STOP** — a bundle compiled without capabilities imposes
nothing at execution; do not work around it with `opa run` on bare .rego
files. A bundle built without `--signing-key` degrades straight back to
the #106 gap (revision alone, no proof) — OPA will refuse to start it in
step 5 regardless (`--verification-key` there has no `--skip-verify`
fallback documented here on purpose).

#### Step 5 — Run OPA as a local server (bundle only, Unix socket, signature verified)

**Verifiable prerequisite**: step 4 green; bundle present;
`policy-verify.pub` installed at `/etc/tbp/policy-verify.pub`.

**Command**:

```bash
# Unix socket, NOT TCP loopback (security review #92, finding A3): a TCP
# port an imposter could occupy and answer allow-to-everything on is
# indistinguishable from the real OPA to pepd/brokerd. The socket's
# owning UID is what pepd/brokerd verify via SO_PEERCRED at every
# connection — run OPA as a DEDICATED user, note its UID (`id -u tbp-opa`).
#
# --bundle (not a bare positional path) is REQUIRED for signature
# verification to activate at all (checked against the real opa binary:
# a positional bundle path silently skips verification even with
# --verification-key set — this is the one flag substitution that would
# make step 4's signing entirely cosmetic).
install -d -o tbp-opa -g tbp-opa -m 0750 /run/tbp
opa run --server --addr unix:///run/tbp/opa.sock \
  --bundle /etc/tbp/bundle.tar.gz \
  --verification-key /etc/tbp/policy-verify.pub --verification-key-id default &
curl -s --unix-socket /run/tbp/opa.sock http://localhost/health
```

**Observable success criterion**: `/health` answers 200 over the socket;
OPA does NOT listen on any TCP port (`ss -ltnp | grep 8181` finds
nothing) — no network exposure, no unauthenticated transport. Proof that
signing is actually enforced, not cosmetic (security review #106): edit
any byte of a `.rego` file inside a copy of the bundle and repackage it
— `opa run` on that copy exits immediately with a digest-mismatch error
and never opens the socket at all; a bundle re-signed with a DIFFERENT
private key than the one behind `policy-verify.pub` is refused the same
way.

**On failure: STOP** — read the OPA log; an invalid bundle, a signature
that does not verify, or a residual socket file gets fixed before pepd,
never after. Never launch pepd against an OPA that failed this step —
`TBP_OPA_REVISION_CHECK_INTERVAL_MS` (step 6) catches a LATER bundle
substitution, it does not retroactively make an already-compromised
startup safe.

#### Step 6 — Start pepd in monitor mode (§5.3)

**Verifiable prerequisite**: steps 2 and 5 green; the cell's issuer
keyring installed (JSON `{"kid_hex": "pubkey_ed25519_hex"}`, 16-byte
kid); the quorum controllers' keyring installed likewise
(`TBP_QUORUM_KEYRING_FILE` — security review #89: no posture switch is
possible without it); cell salt generated locally (≥ 16 bytes, stays
here); `/etc/tbp/pepd.env` at 0600, owned by the service.

**Command**:

```bash
# /etc/tbp/pepd.env — example values, to adapt to the cell:
#   TBP_CELL_ID=cell-a
#   TBP_SALT=<32-char hex — generated locally, never shared>
#   TBP_KEYRING_FILE=/etc/tbp/keyring.json
#   TBP_POLICY_ID=<$POLICY_ID chosen at step 4 — NOT the bundle's own hash>
#   TBP_REGISTRY_DIR=/var/lib/tbp/cell-a
#   TBP_AUDIT_RECORDS=/var/lib/tbp/cell-a-audit/pepd-records.jsonl  # #275: REQUIRED —
#   TBP_AUDIT_RECORDS_KEY_FILE=/etc/tbp/pepd-records.key  # encrypted cleartext of
#                                  # every decision leaf; key 0600 from
#                                  # `tbp-audit keygen -out <file>`; verify
#                                  # with `tbp-audit verify` (deploy/audit.md).
#                                  # Keep the journal OFF the registry dir and
#                                  # the key off the journal's disk if you can
#   TBP_LISTEN_ADDR=127.0.0.1:8443  # DATA plane only (security review #95):
#                                  # /v1/evaluate, /v1/passport/consume
#   TBP_ADMIN_SOCKET=/run/tbp/pepd-admin.sock  # ADMIN plane (security
#                                  # review #95, finding A10): /v1/mode,
#                                  # /healthz. Default shown here; 0660
#                                  # permissions, same doctrine as the
#                                  # broker socket below — NEVER on the
#                                  # agent's TCP channel
#   TBP_OPA_ENDPOINT=http://opa/v1/data/tbp/example/action  # host part
#                                  # is irrelevant over TBP_OPA_SOCKET —
#                                  # the socket dial ignores it
#   TBP_OPA_SOCKET=/run/tbp/opa.sock          # security review #92, A3:
#                                  # OPA now REQUIRED, authenticated by
#                                  # SO_PEERCRED — mandatory unless
#                                  # TBP_OPA_INSECURE_TCP_DEV=1 (dev/lab
#                                  # only, never in production — security
#                                  # review #113: also refused at startup
#                                  # unless /etc/tbp/DEV_ENVIRONMENT
#                                  # exists, a FIXED path hard-coded in
#                                  # the binary, never read from this
#                                  # file — same guard on
#                                  # TBP_OPA_DISABLED_DEV_UNSAFE=1 above,
#                                  # deploy/cellule.md step 4's doc header)
#   TBP_OPA_EXPECTED_UID=$(id -u tbp-opa)     # UID the kernel must report
#                                  # for the OPA process at EVERY connection
#   TBP_QUORUM_MIN=2               # k distinct Ed25519 signatures (security
#                                  # review #89 — no longer a name count)
#   TBP_QUORUM_KEYRING_FILE=/etc/tbp/quorum-keyring.json  # controller
#                                  # public keys pinned (§12), same JSON
#                                  # shape as TBP_KEYRING_FILE — required:
#                                  # without it, NO posture switch is possible
#   TBP_TOPOLOGY=multi              # "mono" or "multi" — security review
#                                  # post-#86 (issue #128): REQUIRED, and
#                                  # checked for consistency against
#                                  # TBP_CELL_BROKER_SOCKET below (multi ⇒
#                                  # present, mono ⇒ absent) — refuses to
#                                  # start otherwise. "multi" here because
#                                  # this example co-locates brokerd
#                                  # (step 7); a standalone scale-1 pepd
#                                  # uses "mono" and drops the line below.
#   TBP_CELL_BROKER_SOCKET=/run/tbp/broker.sock  # required with
#                                  # TBP_TOPOLOGY=multi: live VERIFIED
#                                  # epoch from the co-located brokerd
#                                  # (step 7), §7.2-§7.3. mono ⇒
#                                  # FixedEpoch(0), the explicit scale-1
#                                  # choice (single cell, no fencing)
#   TBP_DURABILITY=async-bounded   # default (T38/#71): verdict at
#                                  # acceptance, bounded catch-up;
#                                  # "sync" = former synchronous path
#   TBP_DURABILITY_WINDOW_MS=1000  # opposability window (default 1 s;
#                                  # floor 4 × checkpoint interval)
#   TBP_OPA_REVISION_CHECK_INTERVAL_MS=10000  # optional (security review
#                                  # #92, A5) — how often the revision OPA
#                                  # ACTUALLY serves is checked against
#                                  # TBP_POLICY_ID; checked once, SYNCHRONOUSLY,
#                                  # before pepd serves at all — a mismatch
#                                  # there refuses to start
#   TBP_MEASURED_BOOT_MANIFEST_FILE=/var/lib/tbp/cell-a-measured-boot.json
#                                  # security review #112: measured boot is
#                                  # now REQUIRED by default — path MUST be
#                                  # outside TBP_REGISTRY_DIR (security
#                                  # review #111: erasing the registry must
#                                  # never also erase the sole witness that
#                                  # this is a restart, not a first boot) ;
#                                  # only TBP_MEASURED_BOOT_DISABLED_DEV_UNSAFE=1
#                                  # (dev/lab only, never in production) may
#                                  # stand in for it
#   TBP_MEASURED_BOOT_ROOT_FILE=/var/lib/tbp/measured-root  # dev-stub root
#                                  # measurer (registry.FileRootMeasurer) —
#                                  # a real deployment substitutes a real
#                                  # TPM/HSM measurer (issue #32)
#   TBP_MEASURED_BOOT_EXPECTED_ROOT=<64 hex chars>  # root hash expected at
#                                  # CheckBoot time
#   TBP_MEASURED_BOOT_POLICY_BUNDLE=/etc/tbp/opa/tbp-example.tar.gz
#   TBP_MEASURED_BOOT_OPA_CONFIG=/etc/tbp/opa-config.yaml
#   TBP_MEASURED_BOOT_BROKER_BINARY=/usr/local/bin/brokerd
#   TBP_MEASURED_BOOT_AI_CONTAINER=<container image digest or path>
#   TBP_MEASURED_BOOT_TRANSITION_PROOF_FILE=/etc/tbp/measured-boot-transition-proof.json
#                                  # (the proof signs the condition the daemon prints
#                                  # when it refuses: measured-boot-transition|from=…|to=…, #236)
#                                  # optional — only present for a DELIBERATE
#                                  # reference re-engagement (bundle/config
#                                  # update). security review #112: replaces
#                                  # the former bare TBP_MEASURED_BOOT_TRANSITION=1
#                                  # flag — now requires a quorum-of-controllers
#                                  # proof (same TBP_QUORUM_KEYRING_FILE as
#                                  # POST /v1/mode, §89/§105), never a plain
#                                  # environment flag alone
#   TBP_PROVISIONING_WITNESS_FILE=/var/lib/tbp/pepd-provisioning-witness.json
#                                  # issue #192: pepd measures the two pinned
#                                  # keyrings it trusts (TBP_KEYRING_FILE,
#                                  # TBP_QUORUM_KEYRING_FILE — derived, not
#                                  # listed here) at every start; a changed
#                                  # file refuses to start. REQUIRED, outside
#                                  # TBP_REGISTRY_DIR (same reason as the
#                                  # measured-boot manifest, #111). Only
#                                  # TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1
#                                  # (dev/lab, needs the DEV_ENVIRONMENT
#                                  # sentinel, never production) may stand in.
#                                  # See "Provisioning files" after step 7.
set -a; . /etc/tbp/pepd.env; set +a
/usr/local/bin/pepd &
curl -s --unix-socket /run/tbp/pepd-admin.sock http://localhost/healthz
curl -s --unix-socket /run/tbp/pepd-admin.sock http://localhost/v1/mode
```

**Observable success criterion**: `/healthz` answers 200;
`GET /v1/mode` returns `{"mode":"monitor"}` on this FIRST startup, the
closed switch is governed (step 8 and
[monitor-to-closed.md](monitor-to-closed.md)); both routes answer ONLY
on the admin Unix socket (security review #95) — a request to
`http://127.0.0.1:8443/v1/mode` (the agent's data-plane port) gets 404;
`cell_log.key` (0600) and `cell_log.vkey` are created in
`TBP_REGISTRY_DIR` (registry key of THE cell — D97 custody). Security
review #93: kill this process and restart it with the SAME
environment — `GET /v1/mode` now returns `{"mode":"refused"}`, and
evaluations are denied even for an otherwise-valid token, until a
quorum-signed `POST /v1/mode` (same shape as step 8) explicitly
reconfirms a posture.

**On failure: STOP** — a startup without keyring, without policy ID or
without salt must fail; if it succeeds, the binary is not the one from
the repo. Closed mode IS NOT the goal of this step. A RESTART that
silently reports `monitor` (instead of `refused`) is the exact
regression security review #93 fixes — never work around it.

#### Step 7 — Build and start brokerd (full decision chain, T37)

**Verifiable prerequisite**: step 6 green; genesis manifest (step 1) in
place under `$GENESIS_HOME` — `epoch0.json` too, UNLESS `TBP_TOPOLOGY=mono`
AND `TBP_CLUSTER_MEMBERS` below names a single cell (mono-cellule mode,
security review #97: with one cell there is no authority conflict to fence
against, so no epoch lease is minted or required — the two-cell example
that follows declares `TBP_TOPOLOGY=multi` and still needs its
`epoch0.json`; security review post-#86, issue #128: the two settings are
checked for consistency, so declaring one without the matching other
refuses to start); PUBLIC operator keys from the contract store installed
(T30 — JSON `["pubkey_ed25519_hex", …]`, ≥ 1); issuer custody provisioned —
EITHER a DEV issuer seed at 0600 (P1 lab/CI only) OR a real HSM/SoftHSM2
token with an Ed25519 key pair generated inside it and its PIN at 0600
(security review #90, point 5 — the private key never leaves the module;
see `src/broker/pkcs11_signer_test.go` for a runnable SoftHSM2 example);
broker salt generated locally (≥ 16 bytes, stays here — the broker's chain
is its OWN, distinct from pepd's).

**Command**:

```bash
go build -o /usr/local/bin/brokerd ./src/broker/cmd/brokerd
/usr/local/bin/brokerd 2>&1 | head -1   # without environment: must refuse

# /etc/tbp/brokerd.env (0600, owned by the service) — example values,
# to adapt to the cell. Issuer custody is EXACTLY ONE of the two blocks
# below — never both, never neither (fail-closed, security review #90.5):
#   TBP_CELL_ID=cell-a
#   TBP_SALT=<32-char hex — salt of the BROKER's chain, generated here>
#   TBP_POLICY_ID=<$POLICY_ID chosen at step 4 — NOT the bundle's own hash>
#   TBP_REGISTRY_DIR=/var/lib/tbp/broker
#   TBP_AUDIT_RECORDS=/var/lib/tbp/broker-audit/records.jsonl  # #275: REQUIRED —
#   TBP_AUDIT_RECORDS_KEY_FILE=/etc/tbp/broker-records.key  # encrypted cleartext of
#                                      # the broker's decision / contract / quorum
#                                      # leaves; key 0600 from `tbp-audit keygen`
#                                      # (deploy/audit.md)
#   TBP_OPA_ENDPOINT=http://opa/v1/data/tbp/example/action  # host part
#                                      # irrelevant over TBP_OPA_SOCKET
#   TBP_OPA_SOCKET=/run/tbp/opa.sock  # security review #92, A3: REQUIRED
#                                      # (authenticated by SO_PEERCRED)
#                                      # unless TBP_OPA_INSECURE_TCP_DEV=1
#                                      # (dev/lab only — security review
#                                      # #113: also refused at startup
#                                      # without /etc/tbp/DEV_ENVIRONMENT,
#                                      # see the issuer custody block below)
#   TBP_OPA_EXPECTED_UID=$(id -u tbp-opa)  # UID the kernel must report
#                                      # for OPA at every connection
#   TBP_TRANSLATOR=structured
#   # --- custody DEV (lab/CI only) — security review #113: unlike the
#   # two OPA dev flags above, this one used to be accepted with NO
#   # dedicated flag at all; refused at startup now unless
#   # /etc/tbp/DEV_ENVIRONMENT exists (fixed path, hard-coded in the
#   # binary — NEVER read from this file, so leaking/misconfiguring it
#   # alone can no longer silently declare a dev environment) ---
#   TBP_ISSUER_SEED_FILE=/etc/tbp/issuer.seed
#   # --- OR custody HSM (production, §12) ---
#   # TBP_ISSUER_PKCS11_MODULE=/usr/lib/softhsm/libsofthsm2.so
#   # TBP_ISSUER_PKCS11_TOKEN_LABEL=cell-a
#   # TBP_ISSUER_PKCS11_KEY_LABEL=issuer-key-1  # security review #114:
#   #                                    # the key MUST be provisioned
#   #                                    # CKA_SENSITIVE=true AND
#   #                                    # CKA_EXTRACTABLE=false — brokerd
#   #                                    # now verifies both at load and
#   #                                    # refuses to start otherwise
#   # TBP_ISSUER_PKCS11_PIN_FILE=/etc/tbp/issuer.pin  # 0600, same custody
#   #                                    # bar as TBP_ISSUER_SEED_FILE —
#   #                                    # security review #114: this is
#   #                                    # still a plaintext secret ON DISK,
#   #                                    # not sealed or channel-restricted;
#   #                                    # prefer a PKCS#11 protected
#   #                                    # authentication path (physical PIN
#   #                                    # pad) when the HSM supports one, or
#   #                                    # a service-managed credential
#   #                                    # (systemd LoadCredential=, a
#   #                                    # dedicated tmpfs cleared on stop)
#   #                                    # over a persistent file like this
#   TBP_GENESIS_DIR=<GENESIS_HOME>
#   TBP_QUORUM_MIN=2
#   TBP_TOPOLOGY=multi                 # "mono" or "multi" — security review
#                                      # post-#86 (issue #128): REQUIRED,
#                                      # and checked for consistency
#                                      # against the member count below
#                                      # (mono ⇒ exactly one, multi ⇒ ≥ 2)
#                                      # — refuses to start otherwise
#   TBP_CLUSTER_MEMBERS=cell-a,cell-b  # ONE cell here (e.g. "cell-a", with
#                                      # TBP_TOPOLOGY=mono) ⇒ mono-cellule
#                                      # mode (#97): no epoch lease minted,
#                                      # epoch0.json not read
#   TBP_OPERATOR_KEYS_FILE=/etc/tbp/operators.json
#   TBP_AGENT_REGISTRY_FILE=/etc/tbp/agents.json  # security review #125:
#                                      # JSON {"<subject>": {"class": 0..3,
#                                      # "quota"?: {"max_volume",
#                                      # "max_window_s"},
#                                      # "transport_identity"?: "<mTLS CN>"}, …}
#                                      # "class" is REQUIRED and any unknown
#                                      # field is refused at load (#241): a
#                                      # typo ("clas") never becomes class 0.
#                                      # — identity/class/quota resolved from
#                                      # HERE, never from the agent's own
#                                      # declaration in its issuance
#                                      # request. Classes 0 (F, financial),
#                                      # 1 (I) and 2 (W) REQUIRE a plan_binding
#                                      # on every action (#177); class 2 also
#                                      # a quorum proof. 3 = outside F/I/W
#                                      # needs neither. The class is the
#                                      # AGENT's (registry), not the action's
#                                      # (issue #195): register every agent
#                                      # that can do an irreversible act as 2.
#                                      # Same out-of-band custody
#                                      # doctrine as TBP_OPERATOR_KEYS_FILE
#                                      # above — no dev escape hatch; a
#                                      # subject absent from this table is
#                                      # refused (agent-unknown), and an
#                                      # agent without a "quota" entry can
#                                      # request no passport at all.
#                                      # transport_identity (security review
#                                      # #162/#163): required for this
#                                      # subject to be usable over the
#                                      # NETWORK mTLS listener below — a
#                                      # request whose client certificate CN
#                                      # does not match is refused
#                                      # (agent-transport-unbound), even
#                                      # though the certificate itself is
#                                      # valid. Absent ⇒ this agent may only
#                                      # be reached over the Unix socket.
#                                      # Present ⇒ the NETWORK only: the
#                                      # Unix socket refuses it
#                                      # (agent-network-only) because it
#                                      # carries no identity — an agent is
#                                      # either a network agent or a socket
#                                      # agent, never both (a local
#                                      # process that can write to the
#                                      # socket must not be able to speak
#                                      # as an agent bound to a certificate).
#   # TBP_SKILL_REGISTRY_FILE=/etc/tbp/skills.json  # OPTIONAL — closes the
#                                      # structural gap confirmed seven times
#                                      # independently across the compliance
#                                      # catalog (#142-#161): TBP had no
#                                      # notion of an installable "skill".
#                                      # JSON {"<action>": {"provenance":
#                                      # "<publisher/source>", "scope":
#                                      # ["<resource>", …], "risk_tier":
#                                      # "low|medium|high|critical"}, …}.
#                                      # risk_tier is REQUIRED (no default
#                                      # tier) and cross-checked against the
#                                      # scope size at startup (low ≤ 8
#                                      # resources, medium ≤ 32, high ≤ 128,
#                                      # critical unbounded — a consistency
#                                      # guard, not a security boundary);
#                                      # brokerd refuses to start otherwise.
#                                      # It is passed to OPA as input.skill
#                                      # {risk_tier, scope_size}; the rule
#                                      # pack policies/rego/pack_skill_tier
#                                      # .rego turns it into gating: high ⇒
#                                      # class I/W (plan), critical ⇒ class W
#                                      # (plan + quorum). Absent ⇒ no
#                                      # skill concept at all — historical
#                                      # behavior unchanged, NOT a hidden
#                                      # regression, a deliberate
#                                      # backward-compatibility choice (opt
#                                      # in for production). Present ⇒
#                                      # fail-closed for EVERY action: one
#                                      # whose name matches no registered
#                                      # skill is refused (skill-unknown),
#                                      # one targeting a resource outside the
#                                      # declared scope is refused
#                                      # (skill-scope-violation) — exact
#                                      # string match only, never a prefix
#                                      # (same confusion class as #107/#108).
#                                      # Same out-of-band custody doctrine as
#                                      # TBP_AGENT_REGISTRY_FILE above: no
#                                      # hot-reload path exists in the code —
#                                      # an agent can never add, widen, or
#                                      # remove a skill entry; only an
#                                      # operator editing this file and
#                                      # restarting brokerd can.
#   TBP_PROVISIONING_WITNESS_FILE=/var/lib/tbp/broker-provisioning-witness.json
#                                      # issue #192: brokerd measures, at every
#                                      # start, the files that carry the cell's
#                                      # trust — operator keys, agent registry,
#                                      # genesis manifest (controllers), skill
#                                      # registry and the mTLS client CA when
#                                      # set. The list is DERIVED from this
#                                      # configuration; the variable
#                                      # TBP_PROVISIONING_EXTRA_FILES holding
#                                      # "name=path,…" adds to it. A changed
#                                      # file refuses to start and names it.
#                                      # REQUIRED, outside TBP_REGISTRY_DIR, a
#                                      # different file from pepd's. Opt-out
#                                      # (dev/lab only, needs the sentinel):
#                                      # TBP_PROVISIONING_DISABLED_DEV_UNSAFE=1.
#                                      # See "Provisioning files".
#   TBP_BROKER_SOCKET=/run/tbp/broker.sock  # DATA plane: POST /v1/actions
#   TBP_BROKER_ADMIN_SOCKET=/run/tbp/broker-admin.sock  # ADMIN plane
#                                      # (security review #95, finding
#                                      # A10): GET /v1/supervision/*.
#                                      # Separate socket, never
#                                      # multiplexed on TBP_BROKER_SOCKET
#   TBP_OPA_REVISION_CHECK_INTERVAL_MS=10000  # optional (security review
#                                      # #92, A5) — checked once,
#                                      # SYNCHRONOUSLY, before brokerd
#                                      # serves; a mismatch refuses to start
#   # --- optional NETWORK listener for the data plane (security review
#   # #124) — the Unix socket above (TBP_BROKER_SOCKET) keeps working
#   # unmodified; these four are OFF by default (Unix-only) and, if used,
#   # are required ALL FOUR TOGETHER — brokerd refuses to start on a
#   # partial set. There is no plaintext TCP option: an unauthenticated
#   # network listener would let an impostor occupying this address issue
#   # tokens indistinguishably from the real broker (same class of fault
#   # as #92.A3, on the issuing side this time) ---
#   # TBP_BROKER_LISTEN_ADDR=0.0.0.0:8443
#   # TBP_BROKER_TLS_CERT_FILE=/etc/tbp/broker-tls.pem     # server leaf
#   # TBP_BROKER_TLS_KEY_FILE=/etc/tbp/broker-tls.key.pem  # 0600
#   # TBP_BROKER_TLS_CLIENT_CA_FILE=/etc/tbp/broker-client-ca.pem
#   #                                      # any peer without a certificate
#   #                                      # signed by this CA is rejected at
#   #                                      # the TLS handshake (TLS 1.3
#   #                                      # minimum, mutual auth required) —
#   #                                      # never reaches the application mux.
#   #                                      # The verified certificate's CN is
#   #                                      # then checked against each
#   #                                      # subject's transport_identity in
#   #                                      # TBP_AGENT_REGISTRY_FILE (security
#   #                                      # review #162/#163): a valid
#   #                                      # certificate claiming a subject it
#   #                                      # isn't registered for is refused
#   #                                      # by the broker itself, not just by
#   #                                      # the TLS handshake.
#   #                                      # USE A CA DEDICATED TO AGENT CLIENT
#   #                                      # CERTIFICATES here — never the CA
#   #                                      # shared with other services or the
#   #                                      # NAC (the spec allows one PKI for both): every certificate it
#   #                                      # signs with a given CN can act as
#   #                                      # that agent. Go's TLS stack already
#   #                                      # requires the clientAuth extended key
#   #                                      # usage; issue agent certificates with
#   #                                      # that EKU only, CN = the agent's
#   #                                      # subject, one per agent, short-lived.
#   #                                      # Identity is the CN only: SAN and
#   #                                      # other profile fields are not
#   #                                      # checked (tracked in the compliance
#   #                                      # catalogue, tbp-compliance/162).
install -m 0644 src/broker/tbp-brokerd.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now tbp-brokerd
curl -s --unix-socket /run/tbp/broker-admin.sock http://localhost/v1/supervision/epoch
```

**Observable success criterion**: the binary builds; launched without
environment, it exits immediately with `brokerd: TBP_CELL_ID requis`
(fail-closed at startup — this refusal IS the criterion); the service is
active; the ADMIN Unix socket answers in GET only:
`/v1/supervision/epoch` returns epoch 0 and the cell's authority,
`/v1/supervision/arbitration` returns the bundle's `policy_id` (step 4)
and an arbitration queue, `/v1/supervision/stats` the broker's
counters; a POST on these views gets 405; the same GET on the DATA
socket (`/run/tbp/broker.sock`) gets 404 — the two planes are on
separate sockets (security review #95). On first startup,
`cell_log.key` (0600) and `cell_log.vkey` are created in
`TBP_REGISTRY_DIR` — the broker's chain is its own (§7.1).

**Multi-cell epoch lease — known operational limit** (issue #197): with
`TBP_TOPOLOGY=multi` the epoch lease must be renewed by an m-of-n signature
BEFORE each expiry (`scripts/genesis renew`, then `POST /v1/epoch/renew` on the
admin socket; TTL 60 s by default, 10–300 s). There is no automatic renewal by
design — an unreachable quorum lets the lease lapse and the cell stops
(fencing, §7). Plan for that cadence, or use `mono` for a single cell; a
sustainable renewal scheme is the open decision in #197.

A renewal token is applied only while its own lease is alive (issue #207): a token
that is authentic but already expired at delivery is refused
(`epoch-token-expired`, traced) and changes nothing — it would otherwise install a
dead epoch over a live one, burn its number `N` (a fresh token at the same `N`
would read as an equivocation) and, in `auto` mode, spend the failover budget.
Sign the renewal just before delivering it; if a token was missed, sign a new one
(a fresh `issued_at`, the same or a higher `N`). Exception: with no epoch yet, the
genesis `epoch0.json` is imported even if expired — `brokerd` starts days after the
ceremony, and the cell does not serve until a live lease is installed.

**On failure: STOP** — a brokerd that starts without salt, without
genesis, without OPA or without operator keys is fail-open: fix the
cause, never work around it. A refused `epoch0` means a genesis that
does not match the manifest: redo the distribution (step 1),
never hand-tinker the token.

## Provisioning files — measured at every start (issue #192)

The measured boot of `pepd` attests four artefacts (bundle, OPA config, `brokerd`
binary, AI container). The files that carry the cell's TRUST are measured by the
daemon that loads them: editing `agents.json` (class W → F, which removes plan and
quorum), adding a key to an operator or controller keyring, or widening a skill's
scope used to pass without any alarm.

- **What is measured.** `brokerd`: operator keys, agent registry, genesis manifest,
  skill registry, mTLS client CA. `pepd`: issuer keyring, quorum keyring. Both also attest the
  **scale settings** (`quorum-settings`: `TBP_QUORUM_MIN` and the topology, #224): lowering k by
  editing the environment is a divergence, and the change is authorised by the k that was attested.
  Adopting this on a cell that already ran takes one transition proof (the new entry changes the
  digest). Both accept
  `TBP_PROVISIONING_EXTRA_FILES`. **`anod` measures itself** (#272): it restarts independently of
  `pepd`, so the daemon that decides what leaves the cell cannot be left to someone else's start-up
  check. `anod` attests its **rules file** (`ano-rules`), issuer keyring, controller keyring
  (authority), **its own binary** (`anod-binary`), the settings that decide what is released
  (`ano-settings`: classifier socket, timeout, grace, bounds) and `k` (`quorum-settings`). Removing a
  pattern, widening `keep_paths` or plugging a classifier between two starts is **refused** without a
  quorum proof bound to (attested state, target state), condition
  `provisioning-transition-anod|from=…|to=…` — the refusal prints it. `anod` needs its own chain and
  witness: `TBP_CELL_ID`, `TBP_SALT`, `TBP_REGISTRY_DIR`, `TBP_PROVISIONING_WITNESS_FILE` (outside the
  registry directory, which must already exist), `TBP_QUORUM_KEYRING_FILE`, `TBP_QUORUM_MIN`; no
  "dev disable" escape hatch exists for `anod`. Upgrading an existing `anod` takes one transition proof.
- **How.** A digest over the sorted (name, SHA-256) list is committed at the first start
  in a witness signed by the cell key, outside `TBP_REGISTRY_DIR`. At each later start the
  digest must match; otherwise the daemon refuses to start, writes a refusal leaf, raises
  the alarm, and names the changed file (never its content).
- **Legitimate change** (new agent, rotated key). Edit the file, then have the
  controllers sign a proof — the same k as class W (`TBP_QUORUM_MIN`): at scale 1 the
  administrator alone signs, k = 1; above that a k-of-n quorum:

  ```bash
  go build -o /usr/local/bin/quorumproof ./src/pep/cmd/quorumproof
  # 1. start WITHOUT a proof: the daemon refuses and prints what to sign, e.g.
  #      condition to sign: provisioning-transition-brokerd|from=<attested digest>|to=<target digest>
  # 2. the controllers sign EXACTLY that condition (they see what they approve)
  quorumproof sign -condition 'provisioning-transition-brokerd|from=…|to=…' -cell cell-a \
    -key /secure/admin.key -out /etc/tbp/provisioning-proof.json
  # 3. in brokerd.env: TBP_PROVISIONING_TRANSITION_PROOF_FILE=/etc/tbp/provisioning-proof.json
  #    restart, check it started, and REMOVE the line (the proof lives 4 minutes by default)
  ```

  Conditions: `provisioning-transition-brokerd` and `provisioning-transition-pepd` (a
  proof for one never works for the other, nor for a posture switch). **A proof is bound
  to the state it approves (issue #236)**: the condition carries the attested digest
  (`from`) and the target digest (`to`). It re-engages no other state — if the file is
  edited again after you signed, the daemon refuses and prints the new condition — and
  it cannot bring the previous state back once the transition has happened. Controllers whose
  keys live in an HSM use `quorumproof message` (what to sign) and `quorumproof assemble`.
- **Who may sign a change (issue #218).** The proof is checked against the controller
  keys *as attested in the witness* (the quorum keyring for `pepd`, the genesis manifest
  for `brokerd`), never against the file now on disk. Otherwise whoever can write that
  file could add their own k keys and sign their own transition. Consequence: a legitimate
  **rotation of the controllers themselves** is signed by the OLD controllers; the new set
  then becomes the reference. Witnesses written before this fix carry no snapshot: an
  unchanged start upgrades them in place, but a *changed* file is refused, with or without
  a proof — re-engage explicitly (below).
- **Re-engaging after a lost witness.** There is nothing attested to check against, so the
  proof falls back to the keyring currently on disk: trust on first use, as at a first
  start. This is an installation act by the administrator, not a transition; keep the
  witness backed up (read-only, off the cell host) and treat its loss as an incident.
- **Adopting this on a cell that already ran.** With no witness and a registry that has
  already lived, the daemon refuses to start (an edited file would otherwise be adopted as
  a "first start", §111): provide one transition proof as above, once.
- **Limits.** Files are loaded once at start (there is no hot reload): a change is caught at
  the next start, not while running. An attacker who holds the cell key AND can write the
  witness can forge it (same trust as the measured-boot manifest). Scale is a setting of
  the proof, not of the mechanism: the same brick runs at every scale.

#### Step 8 — §9.1 measurement points BEFORE any switch (D100)

**Verifiable prerequisite**: steps 6-7 green; the cell has been running in
monitor for an observation window agreed with the supervisor.

**Command**:

```bash
# The T27 harness is the executable reference for the §9.1 measurement points:
go test ./tests/p1_friction/ -run . -count=1
# Cell registry: verified scan (signed checkpoint + Merkle) —
# the independent monitor (deploy/superviseur.md) replays it remotely.
```

**Observable success criterion**: metrics collected (latencies,
would-deny, forwarded); the cell's registry contains
`KindDecision` leaves in monitor (traffic is logged, not blocked).

**On failure: STOP** — no measurement, no closed: the switch is
the [monitor-to-closed.md](monitor-to-closed.md) procedure, with quorum.

## OPA faults: what the cell does, and how a latch is lifted (issue #205)

Every OPA fault (timeout, unreachable, non-200) **denies that request** and
leaves a leaf — that never changes. What changed is the *global* latch (the
fail-closed point that refuses every decision):

- it flips after `TBP_OPA_TRIP_AFTER` **consecutive** faults (default 3; `1`
  restores the former "first fault locks the cell"); a healthy decision resets
  the count. A response that breaks the contract (`opa-bad-response`) flips it
  immediately — that is not an availability fault;
- the background revision watcher flips `opa-revision-unverifiable` when it
  cannot read OPA's revision (an OPA restart). That condition is class I and
  **self-clears**; `opa-revision-mismatch` (a substituted bundle) is class W and
  never does;
- a probe outside the decision path lifts the transient OPA conditions once OPA
  answers **and serves exactly the pinned bundle revision**,
  `TBP_OPA_AUTOCLEAR_PROBES` times in a row (default 3, every
  `TBP_OPA_AUTOCLEAR_INTERVAL_MS`, default 2000). A condition that re-flips soon
  after doubles the probes required (up to ×8), so a flapping OPA neither clears
  by reflex nor drowns the operator in alarms. `TBP_OPA_AUTOCLEAR_PROBES=0`
  disables it: manual lifting only, the strictest profile;
- never lifted automatically: `opa-bad-response`, `opa-revision-mismatch`,
  clock skew, saturation, anchor lag.

Read and lift from the admin socket (access to the socket is the access control,
#95):

```bash
curl -s --unix-socket /run/tbp/pepd-admin.sock http://localhost/v1/failclosed
# class I: an operator decision, traced
curl -s --unix-socket /run/tbp/pepd-admin.sock -X POST \
  -d '{"condition":"opa-bad-response"}' http://localhost/v1/failclosed/clear
# class W: quorum proof signed for THAT condition (replay refused, #105)
quorumproof sign -condition opa-revision-mismatch -cell cell-a -key /etc/tbp/admin.key -out /tmp/p.json
jq '. + {condition:"opa-revision-mismatch"}' /tmp/p.json | curl -s --unix-socket /run/tbp/pepd-admin.sock \
  -X POST -d @- http://localhost/v1/failclosed/clear
```

**Honesty note:** this is resilience against an OPA **process** fault. It does
not make one machine survive its own loss; a second OPA backend and the mirrors
of §7.4 are a separate work item (scale 3).

## Class W quorum proofs are single-use (issue #206)

A class-W action carries a k-of-n quorum proof bound to (action, resource,
policy, epoch, expiry). The broker **consumes** it: the first presentation is
admitted, any later presentation of the same statement is refused
(`quorum-proof-replayed` in the quorum leaf, `quorum-insufficient` to the
caller). The identity of a proof is its signed statement, not its signatures —
a different subset of signers of the same statement is the same authorization.

- To authorize a second execution, the controllers sign a **new** statement
  (another expiry). Collect signatures only once the requester is ready.
- An invalid proof never consumes a statement; a valid one is burned **before**
  the admission leaf and before the plan step, so a crash or a refusal later in
  the chain leaves it burned (re-sign), never replayable.
- The consumed set lives in `TBP_REGISTRY_DIR/quorum_proofs_consumed.json`
  (0600, same custody as `cell_log.key`), survives restarts, purges entries at
  their expiry and never evicts a live one; a full set (4096) refuses. A
  corrupted file refuses to start.
- **Limit:** deleting or replacing that file reopens the replay window for the
  proofs still in their TTL (≤ 300 s). It is part of the cell's state: protect
  it like the registry key.

## Request bounds and read timeouts (issue #209)

`pepd` bounds every request body and the time it takes to read one, on all its
listeners, so that a client of the cell (the data port, the Unix sockets) cannot
hold memory or goroutines with a huge or stalled request:

- `/v1/evaluate` and `/v1/passport/consume`: at most 16 KiB (the largest
  legitimate request — a 1024-byte token, action ≤ 255, resource ≤ 1024, worst-case
  JSON escaping — is about 9 KiB); `/v1/mode` and `/v1/failclosed/clear`: at most
  64 KiB. Beyond the bound the answer is **413**, without the body being processed.
- Every `pepd` and `brokerd` server: 5 s to read the headers, 10 s to read the
  whole request (body included), 60 s of idle keep-alive. A client that sends the
  headers and then stalls is cut at 10 s.
- **Exception, on purpose:** the blocking proxy (`TBP_PROXY_ADDR`) relays real
  traffic, so it has no read timeout (a long upload or stream is legitimate); its
  header and idle timeouts still apply.
- These bounds are not settings: a request that does not fit is not a TBP request.

## systemd units

Hardening pattern: `src/translator/tbp-translator.service` (T24 —
cap-drop, seccomp `@system-service`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`). The broker's unit is DELIVERED:
`src/broker/tbp-brokerd.service` (T37 — own registry alone writable,
no devices, W^X enforced). Still to adapt on the same pattern:
`pepd.service` and `opa.service`, with `EnvironmentFile=/etc/tbp/pepd.env`
(0600). The `src/translator/audit_confinement.sh` script gives the
post-deployment verification pattern, to adapt to the cell's units.

## System hardening

`config/sysctl/99-tbp-hardening.conf` is a starting point to adapt to the
local kernel and network card — never copied as-is (D99).

**OS-level hardening reference** (compliance catalog #158, CIS
Benchmarks): apply the [CIS Debian Linux
Benchmark](https://www.cisecurity.org/benchmark/debian_linux) to the host
before deploying the cell on it. TBP is not a container or OS runtime and
never enforces host-level configuration itself (§7.1: the broker is
cattle, never the root of trust for its own host) — this is a deployment
prerequisite, documented the same way NAC 802.1X is documented in
`router-debian.md`, never a TBP feature.
