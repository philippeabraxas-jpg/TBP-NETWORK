#!/usr/bin/env bash
# scripts/devtest/test_site.sh — tests of the three-machine DEV-TEST site (scripts/devtest/site.sh).
#
# One host plays the three machines: M1 on 127.0.0.11, M2 on 127.0.0.12, M3 as a client, each with its own home
# directory and its own packs, exchanged as files exactly as on three machines. What this proves is the scripts and
# the sequence of deploy/dev-test/site.md — every step and every answer it announces. It does NOT prove that three
# real machines on a real network work: that is what the testers are for.
#
# Needs what site.sh needs (opa, openssl, jq, curl, python3, perl, go or dist/) and a user that may write
# /etc/tbp/DEV_ENVIRONMENT (root, or sudo). It leaves the machine as it found it.
#
#   scripts/devtest/test_site.sh

set -uo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SITE="${SCRIPT_DIR}/site.sh"
SENTINEL=/etc/tbp/DEV_ENVIRONMENT

FAILS=0
ok() { echo "  ok   - $1"; }
bad() { echo "  FAIL - $1"; FAILS=$((FAILS + 1)); }
says() { # says DESCRIPTION EXPECTED-TEXT OUTPUT
  if printf '%s' "$3" | grep -qF -- "$2"; then ok "$1"; else bad "$1 (wanted '$2', got: $(printf '%s' "$3" | tr '\n' ' ' | head -c 260))"; fi
}
refuses() { # refuses DESCRIPTION EXPECTED-TEXT COMMAND...
  local what=$1 text=$2 out rc
  shift 2
  out=$("$@" 2>&1) && rc=0 || rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF -- "$text"; then ok "$what"; else bad "$what (rc=$rc, wanted '$text', got: $(printf '%s' "$out" | tail -2 | tr '\n' ' '))"; fi
}

WORK=$(mktemp -d /tmp/tbpsite.XXXXXX)
H1="${WORK}/m1" H2="${WORK}/m2" H3="${WORK}/m3"
ADDR1=127.0.0.11
ADDR2=127.0.0.12
LABEL="test simulation"
SENTINEL_BEFORE=0
[ -e "${SENTINEL}" ] && SENTINEL_BEFORE=1
if [ "$(id -u)" -eq 0 ]; then export DEVTEST_ALLOW_ROOT=1; fi

M1() { TBP_SITE_HOME="${H1}" "${SITE}" m1 "$@"; }
M2() { TBP_SITE_HOME="${H2}" "${SITE}" m2 "$@"; }
M3() { TBP_SITE_HOME="${H3}" "${SITE}" m3 "$@"; }

cleanup() {
  M3 reset -y >/dev/null 2>&1 || true
  M2 reset -y >/dev/null 2>&1 || true
  M1 reset -y >/dev/null 2>&1 || true
  rm -rf -- "${WORK}"
  if [ "${SENTINEL_BEFORE}" -eq 0 ] && [ -e "${SENTINEL}" ]; then
    if [ -w "$(dirname "${SENTINEL}")" ]; then rm -f "${SENTINEL}"; else sudo rm -f "${SENTINEL}" || true; fi
  fi
}
trap cleanup EXIT

# grant_and_act AGENT ACTION RESOURCE: what the page tells the operator to do on M1, then the agent on M3
grant_and_act() {
  local g cmd
  g=$(M1 grant "$@" 2>&1)
  cmd=$(printf '%s\n' "${g}" | grep 'site.sh m3 act' | sed 's/^ *scripts\/devtest\/site.sh m3 //')
  # shellcheck disable=SC2086
  M3 ${cmd} 2>&1
}
proof_of() { sed -n 's/^proof for pepd: \([^ ]*\).*/\1/p'; }

echo "== rails"
if [ "$(id -u)" -eq 0 ]; then
  refuses "root is refused without the override" "do not run as root" env -u DEVTEST_ALLOW_ROOT TBP_SITE_HOME="${H1}" "${SITE}" m1 init --address "${ADDR1}"
fi
refuses "m1 init needs --address" "--address is required" M1 init
refuses "m2 init needs a pack" "--pack" M2 init --listen "${ADDR2}:9000"
refuses "m3 init needs a pack" "--pack" M3 init --app "http://${ADDR2}:9000"
refuses "a status before init is refused" "not initialised" M1 status
mkdir -p "${WORK}/precious" && echo keep >"${WORK}/precious/file"
refuses "reset refuses a directory that is not a site home" "not a site home" env TBP_SITE_HOME="${WORK}/precious" "${SITE}" m1 reset -y
if [ -f "${WORK}/precious/file" ]; then ok "and leaves its content alone"; else bad "reset deleted a directory that is not a site home"; fi
mkdir -p "${WORK}/empty-pack" && tar -C "${WORK}/empty-pack" -czf "${WORK}/empty.tgz" . 2>/dev/null
refuses "m2 refuses a pack that is not M1's" "lacks" M2 init --pack "${WORK}/empty.tgz" --listen "${ADDR2}:9000"
if [ ! -e "${H2}" ]; then ok "a failed m2 init leaves no half-made home"; else bad "a failed init left ${H2}"; fi

echo "== M1: the cell"
if M1 init --address "${ADDR1}" --env "${LABEL}" >"${WORK}/m1-init.log" 2>&1; then ok "m1 init"; else bad "m1 init: $(tail -5 "${WORK}/m1-init.log" | tr '\n' ' ')"; fi
refuses "a second m1 init is refused" "already exists" M1 init --address "${ADDR1}"
if grep -q '^TBP_QUORUM_MIN=2$' "${H1}/m1.env"; then ok "k = 2"; else bad "TBP_QUORUM_MIN is not 2"; fi
for v in TBP_BROKER_LISTEN_ADDR TBP_BROKER_TLS_CERT_FILE TBP_BROKER_TLS_KEY_FILE TBP_BROKER_TLS_CLIENT_CA_FILE; do
  if grep -q "^${v}=" "${H1}/m1.env"; then :; else bad "m1.env lacks ${v}"; fi
done
ok "the mTLS listener is configured"
if grep -qE '^TBP_(OPA_INSECURE_TCP_DEV|OPA_DISABLED_DEV_UNSAFE|MEASURED_BOOT_DISABLED_DEV_UNSAFE|PROVISIONING_DISABLED_DEV_UNSAFE)=' "${H1}/m1.env"; then
  bad "M1 turns on a development escape hatch other than the issuer seed"
else ok "M1: no development escape hatch other than the issuer seed"; fi
if [ "$(jq -c 'map(.transport_identity)' "${H1}/agents.json" 2>/dev/null || jq -c '[.[] | .transport_identity]' "${H1}/agents.json")" = '["agent-f","agent-i","agent-w"]' ]; then ok "every agent is bound to its certificate"; else bad "agents.json: transport identities"; fi
if [ "$(jq -c 'map(.roles)' "${H1}/operators.json")" = '[["approve"],["approve"],["revoke","arbitrate"],["submit"]]' ]; then ok "operator roles: two approvers, a night duty that only cuts, a submitter"; else bad "operator roles"; fi
# what travels to M2 and M3
m2_files=$(tar -tzf "${H1}/packs/m2.pack.tgz")
m3_files=$(tar -tzf "${H1}/packs/m3.pack.tgz")
if printf '%s' "${m2_files}" | grep -qE 'controller|operator|\.key$|issuer\.seed|signing'; then bad "the pack for M2 carries a private or governance key: $(printf '%s' "${m2_files}" | grep -E 'controller|operator|\.key$|issuer|signing' | tr '\n' ' ')"; else ok "the pack for M2 carries no private key and no governance key"; fi
if printf '%s' "${m3_files}" | grep -qE 'controller|operator|issuer|signing|ca\.key|server-ca\.key|agent-ca\.key'; then bad "the pack for M3 carries a governance key or a CA key"; else ok "the pack for M3 carries no governance key and no CA key"; fi
if printf '%s' "${m3_files}" | grep -q 'agents/agent-i.key'; then ok "the pack for M3 carries the agents' keys (and only those)"; else bad "the pack for M3 lacks the agents' keys"; fi
# M2 and M3 need no development sentinel: start M2 while the sentinel is away (on one host M1 made it for all three)
asidefile="${WORK}/sentinel.aside"
sudo_if_needed() { if [ -w "$(dirname "${SENTINEL}")" ]; then "$@"; else sudo "$@"; fi; }
if [ -e "${SENTINEL}" ] && sudo_if_needed mv -- "${SENTINEL}" "${asidefile}" 2>/dev/null; then
  if M2 init --pack "${H1}/packs/m2.pack.tgz" --listen "${ADDR2}:9000" >"${WORK}/m2-nosentinel.log" 2>&1 && M2 up >>"${WORK}/m2-nosentinel.log" 2>&1; then
    ok "M2 starts with no development sentinel on the machine"
  else
    bad "M2 needed the sentinel: $(tail -5 "${WORK}/m2-nosentinel.log" | tr '\n' ' ')"
  fi
  M2 reset -y >/dev/null 2>&1
  sudo_if_needed mv -- "${asidefile}" "${SENTINEL}"
else
  echo "  skip - cannot move the sentinel away here"
fi
if M1 up >"${WORK}/m1-up.log" 2>&1; then ok "m1 up"; else bad "m1 up: $(tail -6 "${WORK}/m1-up.log" | tr '\n' ' ')"; fi
refuses "m1 up while running is refused" "already running" M1 up
if grep -q "ALARME sécurité (revue #113)" "${H1}/log/brokerd.log"; then ok "M1 raises the development alarm at start"; else bad "no development alarm on M1"; fi

echo "== M2: the application server"
if M2 init --pack "${H1}/packs/m2.pack.tgz" --listen "${ADDR2}:9000" --env "${LABEL}" >"${WORK}/m2-init.log" 2>&1; then ok "m2 init"; else bad "m2 init: $(tail -5 "${WORK}/m2-init.log" | tr '\n' ' ')"; fi
if grep -qE '^TBP_[A-Z_]*DEV[A-Z_]*=' "${H2}/m2.env"; then bad "M2 turns on a development escape hatch"; else ok "M2: no development escape hatch at all (no sentinel needed)"; fi
if M2 up >"${WORK}/m2-up.log" 2>&1; then ok "m2 up"; else bad "m2 up: $(tail -8 "${WORK}/m2-up.log" | tr '\n' ' ')"; fi
says "pepd starts in monitor on its first start" "posture: monitor" "$(cat "${WORK}/m2-up.log")"

echo "== M3: the agent"
if M3 init --pack "${H1}/packs/m3.pack.tgz" --app "http://${ADDR2}:9000" --env "${LABEL}" >"${WORK}/m3-init.log" 2>&1; then ok "m3 init"; else bad "m3 init: $(tail -5 "${WORK}/m3-init.log" | tr '\n' ' ')"; fi
refuses "m3 refuses M2's pack" "lacks" env TBP_SITE_HOME="${WORK}/m3b" "${SITE}" m3 init --pack "${H1}/packs/m2.pack.tgz" --app "http://${ADDR2}:9000"
if M3 check >"${WORK}/m3-check.log" 2>&1; then ok "m3 check: the plumbing works"; else bad "m3 check: $(grep -E 'FAIL' "${WORK}/m3-check.log" | tr '\n' ' ')"; fi

echo "== the functional scenario of deploy/dev-test/site.md, in monitor"
says "no plan: the cell refuses" "plan-binding-required" "$(M3 act agent-i read doc-1 2>&1)"
out=$(grant_and_act agent-i read doc-1)
says "a granted action: the cell issues a token" '"allow":true' "${out}"
says "…and the application on M2 executes it, pepd having checked the token" '"executed": "read doc-1"' "${out}"
says "monitor: the same token presented again is a would-deny that is not blocked" '"reason": "replay"' "$(M3 call 2>&1)"
grant_and_act agent-i read doc-1 >/dev/null
says "monitor: a token for another resource is a would-deny that is not blocked" '"reason": "scope-mismatch"' "$(M3 call read doc-9 2>&1)"
grant_and_act agent-i read doc-1 >/dev/null
says "monitor: a forged token is a would-deny that is not blocked" '"reason": "bad-signature"' "$(M3 call --forge 2>&1)"
says "class W without the controllers' proof" "quorum-required" "$(g=$(M1 grant agent-w read doc-1 2>&1); cmd=$(printf '%s\n' "${g}" | grep 'site.sh m3 act' | sed 's/^ *scripts\/devtest\/site.sh m3 //;s/ --proof .*//'); M3 ${cmd} 2>&1)"
out=$(grant_and_act agent-w read doc-1)
says "class W with two operators and two controllers" '"executed": "read doc-1"' "${out}"
says "an agent using another agent's certificate" "agent-transport-unbound" "$(M3 act agent-i read doc-1 --as agent-w 2>&1)"
says "no client certificate: refused at the TLS handshake" "refused at the TLS handshake" "$(M3 act agent-i read doc-1 --no-cert 2>&1)"

echo "== the operator's side, as a person does it: m1 sign"
out=$(printf 'sign\n' | M1 sign agent-i read doc-s1 2>&1)
says "sign shows the plan in clear" "may      : read doc-s1" "${out}"
says "sign recomputes the hash itself" "is the hash of this plan" "${out}"
cmd=$(printf '%s\n' "${out}" | grep 'site.sh m3 act' | sed 's/^ *scripts\/devtest\/site.sh m3 //')
# shellcheck disable=SC2086
says "…and what the operator signed is what the agent can then do" '"executed": "read doc-s1"' "$(M3 ${cmd} 2>&1)"
sleep 1.1
out=$(printf 'no\n' | M1 sign agent-i read doc-s2 2>&1) && rc=0 || rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "nothing was approved" && ! printf '%s' "${out}" | grep -q "plan approved"; then ok "an operator who does not type 'sign' approves nothing"; else bad "sign approved without the word (rc=${rc})"; fi
out=$(M1 sign agent-i read doc-s3 </dev/null 2>&1) && rc=0 || rc=$?
if [ "${rc}" -ne 0 ] && ! printf '%s' "${out}" | grep -q "plan approved"; then ok "no answer at all approves nothing"; else bad "sign approved with no answer"; fi
out=$(printf 'sign\nno\n' | M1 sign agent-w read doc-s4 2>&1) && rc=0 || rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "no controllers' proof" && ! printf '%s' "${out}" | grep -q -- "--proof"; then ok "class W: the operators sign, the controllers refuse: no proof is made"; else bad "class W: a proof was made without the controllers' confirmation"; fi
# a broker that sealed ANOTHER plan than the one shown: the operator's own recomputation must stop it
sed 's|^  cp "${w}/plan.json" "${w}/submitted-plan.json".*$|  jq '"'"'.steps[0].resource="doc-other"'"'"' "${w}/plan.json" >"${w}/submitted-plan.json"|' "${SITE}" >"${WORK}/site-forged.sh"
chmod +x "${WORK}/site-forged.sh"
if cmp -s "${SITE}" "${WORK}/site-forged.sh"; then bad "the forged copy of site.sh changed nothing"; else
  out=$(TBP_SITE_HOME="${H1}" "${WORK}/site-forged.sh" m1 sign agent-i read doc-s5 --yes 2>&1) && rc=0 || rc=$?
  if [ "${rc}" -ne 0 ] && printf '%s' "${out}" | grep -q "NOTHING is signed" && printf '%s' "${out}" | grep -q "DIFFÉRENT" && ! printf '%s' "${out}" | grep -q "plan approved"; then
    ok "the broker sealed another plan: the operator's recomputation refuses, even with --yes"
  else bad "a plan the broker sealed differently was signed (rc=${rc}): $(printf '%s' "${out}" | tail -3 | tr '\n' ' ')"; fi
fi

echo "== closing and reopening pepd: governed by the controllers"
p=$(M1 mode-proof closed 2>&1 | proof_of)
says "one controller closes (restricting is not widening)" '"mode":"closed"' "$(M2 mode closed --proof "${p}" 2>&1)"
grant_and_act agent-i read doc-1 >/dev/null
says "closed: a replayed token is blocked (HTTP 403)" "[403]" "$(M3 call 2>&1)"
grant_and_act agent-i read doc-1 >/dev/null
says "closed: a token for another resource is blocked" '"reason": "scope-mismatch"' "$(M3 call read doc-9 2>&1)"
grant_and_act agent-i read doc-1 >/dev/null
says "closed: a forged token is blocked" '"reason": "bad-signature"' "$(M3 call --forge 2>&1)"
out=$(grant_and_act agent-i read doc-1)
says "closed: a valid token still passes" '"executed": "read doc-1"' "${out}"
p=$(M1 mode-proof monitor --controllers 1 2>&1 | proof_of)
says "reopening with one controller is refused" "[403]" "$(M2 mode monitor --proof "${p}" 2>&1)"
p=$(M1 mode-proof monitor 2>&1 | proof_of)
says "reopening with two controllers" '"mode":"monitor"' "$(M2 mode monitor --proof "${p}" 2>&1)"
refuses "a closed-proof cannot be used to reopen" "not for 'monitor'" env TBP_SITE_HOME="${H2}" "${SITE}" m2 mode monitor --proof "$(M1 mode-proof closed 2>&1 | proof_of)"

echo "== the network exposure"
listen_out=$(M1 listeners 2>&1)
says "M1's cell listens on the address it was given" "${ADDR1}:8443" "${listen_out}"
says "M2's application listens on the address it was given" "${ADDR2}:9000" "${listen_out}"
says "pepd listens on the loopback only" "127.0.0.1:8443" "${listen_out}"
if printf '%s' "${listen_out}" | grep -qE '^ +(0\.0\.0\.0|\[::\]):(8443|9000)$'; then bad "something listens on every interface on 8443 or 9000"; else ok "nothing listens on every interface on 8443 or 9000"; fi
if curl -sS -m 3 -o /dev/null "http://${ADDR2}:8443/v1/evaluate" 2>/dev/null; then bad "pepd's data port answered on M2's network address"; else ok "pepd's data port is not reachable on M2's network address (from M3)"; fi
plain=$(curl -sS -m 3 -X POST -d '{"subject":"agent-i","intent":"{}"}' "http://${ADDR1}:8443/v1/actions" 2>&1 || true)
if printf '%s' "${plain}" | grep -q '"allow"'; then bad "the cell took a decision over plain HTTP"; else says "the cell takes no decision over plain HTTP" "HTTPS server" "${plain}"; fi

echo "== files changed by hand stop each machine, naming the reason"
M2 down >/dev/null 2>&1
cp -- "${H2}/issuer-keyring.json" "${WORK}/ik.bak"
jq '. + {"00112233445566778899aabbccddeeff":"'"$(printf 'ab%.0s' $(seq 1 32))"'"}' "${WORK}/ik.bak" >"${H2}/issuer-keyring.json"
if M2 up >/dev/null 2>&1; then bad "M2 started with a second issuer key pinned"; else
  says "M2: a second issuer key in the pinned keyring" "provisioning-divergence" "$(cat "${H2}/log/pepd.log")"; fi
cp -- "${WORK}/ik.bak" "${H2}/issuer-keyring.json"
cp -- "${H2}/m2.env" "${WORK}/m2.env.bak"
sed -i 's/^TBP_QUORUM_MIN=2$/TBP_QUORUM_MIN=1/' "${H2}/m2.env"
if M2 up >/dev/null 2>&1; then bad "M2 started with a lowered quorum"; else says "M2: the quorum lowered in the environment" "quorum-settings" "$(cat "${H2}/log/pepd.log")"; fi
cp -- "${WORK}/m2.env.bak" "${H2}/m2.env"
echo changed >>"${H2}/app/ai-container.txt"
if M2 up >/dev/null 2>&1; then bad "M2 started with a changed measured file"; else says "M2: a measured file changed" "manifest-boot-divergence" "$(cat "${H2}/log/pepd.log")"; fi
sed -i '$d' "${H2}/app/ai-container.txt"
if pgrep -f -- "${H2}/bin/" >/dev/null 2>&1; then bad "a failed M2 up left a process running"; else ok "a failed M2 up leaves nothing running"; fi

echo "== a restart: pepd comes back refused until the controllers reconfirm"
if M2 up >"${WORK}/m2-up2.log" 2>&1; then ok "M2 restarted with its files restored"; else bad "M2 restart: $(tail -5 "${WORK}/m2-up2.log" | tr '\n' ' ')"; fi
says "pepd's posture after a restart" "posture: refused" "$(cat "${WORK}/m2-up2.log")"
out=$(grant_and_act agent-i read doc-1)
says "refused: even a valid token is not forwarded (HTTP 403)" "[403]" "${out}"
says "…and the verdict says so: forwarded is false (the application acts on that, not on allow)" '"forwarded": false' "${out}"
p=$(M1 mode-proof monitor 2>&1 | proof_of)
says "two controllers reconfirm monitor" '"mode":"monitor"' "$(M2 mode monitor --proof "${p}" 2>&1)"
out=$(grant_and_act agent-i read doc-1)
says "and the application serves again" '"executed": "read doc-1"' "${out}"

echo "== M1 files changed by hand"
M1 down >/dev/null 2>&1
cp -- "${H1}/m1.env" "${WORK}/m1.env.bak"
sed -i 's/^TBP_QUORUM_MIN=2$/TBP_QUORUM_MIN=1/' "${H1}/m1.env"
refuses "M1: the quorum lowered in the environment" "exited at start" M1 up
says "…naming quorum-settings" "quorum-settings" "$(cat "${H1}/log/brokerd.log")"
if pgrep -f -- "${H1}/bin/" >/dev/null 2>&1; then bad "a failed M1 up left a process running"; else ok "a failed M1 up leaves nothing running"; fi
cp -- "${WORK}/m1.env.bak" "${H1}/m1.env"
if M1 up >/dev/null 2>&1 && M3 check >/dev/null 2>&1; then ok "M1 restored: it starts and the plumbing works again"; else bad "M1 restored but the plumbing does not work"; fi

echo "== reports: numbers for the issue, and nothing secret in them"
M1 report >"${WORK}/r1.md" 2>&1; M2 report >"${WORK}/r2.md" 2>&1; M3 report >"${WORK}/r3.md" 2>&1
for r in r1 r2 r3; do
  for needle in "environment: ${LABEL}" "machine:" "system:"; do
    if grep -qF -- "${needle}" "${WORK}/${r}.md"; then :; else bad "${r} lacks '${needle}'"; fi
  done
done
ok "each report names its machine and the environment the tester gave"
says "M1's report has the broker's counters" "broker counters" "$(cat "${WORK}/r1.md")"
says "M2's report has pepd's posture" "pepd posture" "$(cat "${WORK}/r2.md")"
says "M2's report has the verdict latency" "p95" "$(cat "${WORK}/r2.md")"
says "M3's report has the round trip to the cell" "decision round trip to the cell" "$(cat "${WORK}/r3.md")"
leak=0
for secret in "${H1}" "${H2}" "${H3}" "${ADDR1}" "${ADDR2}" "$(cat "${H1}/issuer.seed")" "$(cat "${H1}/keys/controller-1.key")" "$(cat "${H3}/agents/agent-i.key" | sed -n 2p)" "$(hostname)"; do
  [ -n "${secret}" ] || continue
  for r in r1 r2 r3; do
    if grep -qF -- "${secret}" "${WORK}/${r}.md"; then leak=1; echo "      ${r} contains: ${secret:0:14}…"; fi
  done
done
if [ "${leak}" -eq 0 ]; then ok "no report holds a key, seed, path, address or host name"; else bad "a report leaks something"; fi

echo "== the page (both languages) still names what it announces"
for kw in "site.sh m1 sign" "m1 grant" "site.sh m3 act" "mode-proof" "forwarded" "agent-transport-unbound" "provisioning-divergence" "manifest-boot-divergence" "quorum-settings" "HTTPS server" "report" "SECURITY.md" "M1" "M2" "M3"; do
  for lang in site.md site.fr.md; do
    if grep -qF -- "${kw}" "${SCRIPT_DIR}/../../deploy/dev-test/${lang}"; then :; else bad "deploy/dev-test/${lang} no longer mentions '${kw}'"; fi
  done
done
ok "deploy/dev-test/site.md and site.fr.md name every documented answer"

echo "== reset"
M3 reset -y >/dev/null 2>&1; M2 reset -y >/dev/null 2>&1; M1 reset -y >/dev/null 2>&1
if [ ! -e "${H1}" ] && [ ! -e "${H2}" ] && [ ! -e "${H3}" ]; then ok "reset deletes the three homes"; else bad "reset left a home"; fi
if [ "${SENTINEL_BEFORE}" -eq 0 ]; then
  if [ ! -e "${SENTINEL}" ]; then ok "reset removes the sentinel it made"; else bad "reset left the sentinel it made"; fi
else
  if [ -e "${SENTINEL}" ]; then ok "reset leaves a sentinel it did not make"; else bad "reset removed a sentinel it did not make"; fi
fi
if pgrep -f -- "${WORK}" >/dev/null 2>&1; then bad "a process of the test is still running"; else ok "nothing of the test is left running"; fi

echo
if [ "${FAILS}" -eq 0 ]; then echo "test_site: all good"; else echo "test_site: ${FAILS} failure(s)"; exit 1; fi
