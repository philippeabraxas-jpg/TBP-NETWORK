#!/usr/bin/env bash
# scripts/devtest/test_devtest.sh — tests of the DEV-TEST bootstrap (scripts/devtest/devtest.sh).
#
# Two kinds of test, both against the real binaries:
#   - the rails: what the script REFUSES (a second init, a machine that looks like production, root without the
#     override, a socket path too long, a half-made home) — each one must fail, with the reason named;
#   - the cycle: init, up, demo, down, up again, demo, and the point of the whole exercise: the scale cannot be
#     lowered by editing the environment (the provisioning witness refuses, #224).
#
# Needs what devtest.sh needs (opa, openssl, jq, curl, go or dist/) and a user that may write
# /etc/tbp/DEV_ENVIRONMENT (root, or sudo). It leaves the machine as it found it: a sentinel that was there before
# stays, one the test made is removed.
#
#   scripts/devtest/test_devtest.sh

set -uo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEVTEST="${SCRIPT_DIR}/devtest.sh"
SENTINEL=/etc/tbp/DEV_ENVIRONMENT

FAILS=0
ok() { echo "  ok   - $1"; }
bad() { echo "  FAIL - $1"; FAILS=$((FAILS + 1)); }

# refuses DESCRIPTION EXPECTED-TEXT COMMAND... : the command must fail and its output must contain the text
refuses() {
  local what=$1 text=$2 out rc
  shift 2
  out=$("$@" 2>&1) && rc=0 || rc=$?
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qF -- "$text"; then ok "$what"; else bad "$what (rc=$rc, wanted '$text', got: $(printf '%s' "$out" | tail -2 | tr '\n' ' '))"; fi
}

WORK=$(mktemp -d /tmp/tbpdt.XXXXXX)
export TBP_DEVTEST_HOME="${WORK}/h"
SENTINEL_BEFORE=0
[ -e "${SENTINEL}" ] && SENTINEL_BEFORE=1
if [ "$(id -u)" -eq 0 ]; then export DEVTEST_ALLOW_ROOT=1; fi

cleanup() {
  "${DEVTEST}" reset -y >/dev/null 2>&1 || true
  rm -rf -- "${WORK}"
  if [ "${SENTINEL_BEFORE}" -eq 0 ] && [ -e "${SENTINEL}" ]; then
    if [ -w "$(dirname "${SENTINEL}")" ]; then rm -f "${SENTINEL}"; else sudo rm -f "${SENTINEL}" || true; fi
  fi
}
trap cleanup EXIT

echo "== rails"
if [ "$(id -u)" -eq 0 ]; then
  refuses "root is refused without the override" "do not run as root" env -u DEVTEST_ALLOW_ROOT "${DEVTEST}" init
fi
refuses "a socket path too long is refused" "too long" env TBP_DEVTEST_HOME="${WORK}/$(printf 'x%.0s' $(seq 1 90))" "${DEVTEST}" init
refuses "up before init is refused" "not initialised" "${DEVTEST}" up
# reset runs rm -rf on a directory the user names: it must refuse one that init did not make
mkdir -p "${WORK}/precious"
echo keep >"${WORK}/precious/file"
refuses "reset refuses a directory that is not a devtest home" "not a devtest home" env TBP_DEVTEST_HOME="${WORK}/precious" "${DEVTEST}" reset -y
if [ -f "${WORK}/precious/file" ]; then ok "and leaves its content alone"; else bad "reset deleted a directory that is not a devtest home"; fi
refuses "status before init is refused" "not initialised" "${DEVTEST}" status
# a half-made home is removed: a quorumproof that fails stops init at the first key
FAKEBIN="${WORK}/fakebin"
mkdir -p "${FAKEBIN}"
printf '#!/bin/sh\nexit 1\n' >"${FAKEBIN}/quorumproof"
printf '#!/bin/sh\nexit 0\n' >"${FAKEBIN}/brokerd"
printf '#!/bin/sh\nexit 0\n' >"${FAKEBIN}/tbp-audit"
chmod +x "${FAKEBIN}"/*
refuses "a failing init stops with a reason" "quorumproof keygen failed" env DEVTEST_BIN_DIR="${FAKEBIN}" "${DEVTEST}" init
if [ ! -e "${TBP_DEVTEST_HOME}" ]; then ok "a failed init leaves no half-made home"; else bad "a failed init left ${TBP_DEVTEST_HOME}"; fi

echo "== the cycle"
if "${DEVTEST}" init >"${WORK}/init.log" 2>&1; then ok "init"; else bad "init: $(tail -3 "${WORK}/init.log" | tr '\n' ' ')"; fi
refuses "a second init is refused" "already exists" "${DEVTEST}" init
if [ -e "${SENTINEL}" ]; then ok "the development sentinel is declared"; else bad "no sentinel"; fi
# the only development switch in use is the issuer seed; nothing else of #113 is on
if grep -qE '^TBP_(OPA_INSECURE_TCP_DEV|OPA_DISABLED_DEV_UNSAFE|MEASURED_BOOT_DISABLED_DEV_UNSAFE|PROVISIONING_DISABLED_DEV_UNSAFE)=' "${TBP_DEVTEST_HOME}/brokerd.env"; then
  bad "the environment turns on a development escape hatch other than the issuer seed"
else
  ok "no development escape hatch other than the issuer seed"
fi
if grep -q '^TBP_QUORUM_MIN=2$' "${TBP_DEVTEST_HOME}/brokerd.env"; then ok "k = 2"; else bad "TBP_QUORUM_MIN is not 2"; fi
if [ "$(jq '.pubkeys | length' "${TBP_DEVTEST_HOME}/genesis/manifest.json")" = "3" ]; then ok "three controllers (n = 3)"; else bad "the manifest does not hold three controllers"; fi
if [ "$(jq -c 'map(.roles)' "${TBP_DEVTEST_HOME}/operators.json")" = '[["approve"],["approve"],["revoke","arbitrate"],["submit"]]' ]; then ok "operator roles: two approvers, a night duty that only cuts, a submitter"; else bad "operator roles are not the expected split"; fi
if "${DEVTEST}" up >"${WORK}/up.log" 2>&1; then ok "up"; else bad "up: $(tail -12 "${WORK}/up.log" | tr '\n' ' ')"; fi
if "${DEVTEST}" status >/dev/null 2>&1; then ok "status"; else bad "status"; fi
refuses "up while running is refused" "already running" "${DEVTEST}" up
if "${DEVTEST}" demo >"${WORK}/demo.log" 2>&1; then ok "demo"; else bad "demo: $(tail -12 "${WORK}/demo.log" | tr '\n' ' ')"; fi
if [ "$(grep -c '^  ok   -' "${WORK}/demo.log")" -eq 12 ]; then ok "the demo ran all its 12 checks"; else bad "the demo ran $(grep -c '^  ok   -' "${WORK}/demo.log") checks, not 12"; fi
# the demo must be able to fail: a copy that expects the wrong refusal reason must NOT pass
sed 's/"plan-binding-required"/"a-reason-the-broker-never-gives"/' "${DEVTEST}" >"${WORK}/devtest-wrong.sh"
chmod +x "${WORK}/devtest-wrong.sh"
if "${WORK}/devtest-wrong.sh" demo >"${WORK}/demo-wrong.log" 2>&1; then bad "the demo passed with a wrong expectation: it checks nothing"; else ok "the demo fails when an expectation is wrong"; fi
if grep -q "ALARME sécurité (revue #113)" "${TBP_DEVTEST_HOME}/log/brokerd.log"; then ok "the development alarm is raised at start"; else bad "no development alarm in the broker log"; fi

echo "== the scale cannot be lowered by editing the environment (#224)"
"${DEVTEST}" down >/dev/null 2>&1
cp -- "${TBP_DEVTEST_HOME}/brokerd.env" "${WORK}/brokerd.env.orig"
sed -i 's/^TBP_QUORUM_MIN=2$/TBP_QUORUM_MIN=1/' "${TBP_DEVTEST_HOME}/brokerd.env"
refuses "TBP_QUORUM_MIN=1 is refused at start" "exited at start" "${DEVTEST}" up
if pgrep -f -- "${TBP_DEVTEST_HOME}/bin/" >/dev/null 2>&1; then bad "a failed up left a process running"; else ok "a failed up leaves nothing running"; fi
if grep -q "quorum-settings" "${TBP_DEVTEST_HOME}/log/brokerd.log"; then ok "brokerd names quorum-settings"; else bad "brokerd did not name quorum-settings"; fi
"${DEVTEST}" down >/dev/null 2>&1
cp -- "${WORK}/brokerd.env.orig" "${TBP_DEVTEST_HOME}/brokerd.env"
if "${DEVTEST}" up >/dev/null 2>&1 && "${DEVTEST}" demo >/dev/null 2>&1; then ok "restored, it starts and the demo passes again"; else bad "restored environment does not start"; fi

echo "== the attempts written in deploy/dev-test/solo.md give the answers it announces"
# The documentation says what each attempt must return; if the cell stops saying it, this fails, and so does the doc.
eval "$("${DEVTEST}" env)"
post() { curl -sS --unix-socket "$1" -X POST "${@:3}" -w ' [%{http_code}]\n' "http://localhost$2"; }
says() { # says DESCRIPTION EXPECTED-TEXT OUTPUT
  if printf '%s' "$3" | grep -qF -- "$2"; then ok "$1"; else bad "$1 (wanted '$2', got: $(printf '%s' "$3" | head -c 200))"; fi
}
says "agent: two subjects" "duplicate-key" "$(post "${DT_AGENT_SOCK}" /v1/actions -d '{"subject":"agent-i","subject":"agent-w","intent":"{}"}')"
says "agent: an unknown field" "unknown-field" "$(post "${DT_AGENT_SOCK}" /v1/actions -d '{"subject":"agent-i","intent":"{}","class":2}')"
says "agent: a lower class claimed for a class-W agent changes nothing" "quorum-required" "$(post "${DT_AGENT_SOCK}" /v1/actions -d '{"subject":"agent-w","intent":"{\"action\":\"read\",\"resource\":\"doc-1\",\"class\":1}"}')"
head -c 70000 /dev/zero | tr '\0' a >"${WORK}/big"
says "agent: a body over 64 KiB" "body-unreadable" "$(post "${DT_AGENT_SOCK}" /v1/actions --data-binary @"${WORK}/big")"
echo '{"subject":"agent-i","steps":[{"action":"read","resource":"doc-9","params_hex":""}]}' >"${WORK}/plan.json"
quorumproof plansubmit -cell "${DT_CELL}" -plan "${WORK}/plan.json" -key "${DT_KEYS}/operator-4.key" -out "${WORK}/s4.json" >/dev/null 2>&1
H=$(curl -sS --unix-socket "${DT_ADMIN_SOCK}" -X POST -d @"${WORK}/s4.json" http://localhost/v1/supervision/plan/submit | jq -r .plan_hash)
if [ "${#H}" -eq 64 ]; then ok "operator: the signed plan of the README is accepted"; else bad "operator: the signed plan was not accepted (${H})"; fi
says "operator: a plan without a signature" "non signée" "$(post "${DT_ADMIN_SOCK}" /v1/supervision/plan/submit -d @"${WORK}/plan.json")"
quorumproof plansubmit -cell "${DT_CELL}" -plan "${WORK}/plan.json" -key "${DT_KEYS}/operator-1.key" -out "${WORK}/s.json" >/dev/null 2>&1
says "operator: a key that cannot submit" "rôle de soumission" "$(post "${DT_ADMIN_SOCK}" /v1/supervision/plan/submit -d @"${WORK}/s.json")"
quorumproof plansubmit -cell cell-other -plan "${WORK}/plan.json" -key "${DT_KEYS}/operator-4.key" -out "${WORK}/s.json" >/dev/null 2>&1
says "operator: a plan signed for another cell" "signature de soumission invalide" "$(post "${DT_ADMIN_SOCK}" /v1/supervision/plan/submit -d @"${WORK}/s.json")"
quorumproof planapprove -plan-hash "${H}" -expires-at "$(date -u -d '+30 minutes' +%Y-%m-%dT%H:%M:%SZ)" -key "${DT_KEYS}/operator-4.key" -out "${WORK}/a.json" >/dev/null 2>&1
says "operator: approval by the key that submitted" "rôle d'approbation" "$(post "${DT_ADMIN_SOCK}" /v1/supervision/plan/approve -d @"${WORK}/a.json")"
quorumproof planrevoke -plan-hash "${H}" -key "${DT_KEYS}/operator-1.key" -out "${WORK}/r.json" >/dev/null 2>&1
says "operator: revocation by an approver's key" "rôle de révocation" "$(post "${DT_ADMIN_SOCK}" /v1/supervision/plan/revoke -d @"${WORK}/r.json")"
out=$(quorumproof planhash -cell "${DT_CELL}" -policy-id "${DT_POLICY_ID}" -submitted-at 2026-01-01T00:00:00Z -plan "${WORK}/plan.json" -expect "$(printf 'a%.0s' $(seq 1 64))" 2>&1) && rc=0 || rc=$?
if [ "$rc" -eq 1 ]; then says "operator: a hash that is not the broker's" "DIFFÉRENT" "${out}"; else bad "operator: planhash with a wrong -expect exited ${rc}, not 1"; fi

echo "== a file changed by hand stops the cell, with the reason the README announces"
file_attack() { # file_attack DESCRIPTION FILE LOGFILE EXPECTED-TEXT MUTATION-COMMAND
  local what=$1 f=$2 logf=$3 text=$4 mutate=$5
  "${DEVTEST}" down >/dev/null 2>&1
  cp -- "${f}" "${WORK}/file.bak"
  eval "${mutate}"
  if "${DEVTEST}" up >"${WORK}/up-attack.log" 2>&1; then bad "${what}: the cell started"; else
    if grep -qF -- "${text}" "${TBP_DEVTEST_HOME}/log/${logf}"; then ok "${what}"; else bad "${what} (no '${text}' in ${logf})"; fi
  fi
  cp -- "${WORK}/file.bak" "${f}"
}
file_attack "an agent added to agents.json by hand" "${TBP_DEVTEST_HOME}/agents.json" brokerd.log "agent-registry" \
  "jq '. + {\"agent-evil\":{\"class\":3}}' '${WORK}/file.bak' >'${TBP_DEVTEST_HOME}/agents.json'"
file_attack "one byte of the signed bundle altered" "${TBP_DEVTEST_HOME}/opa/bundle.tar.gz" opa.log "load error: bundle" \
  "size=\$(stat -c%s '${TBP_DEVTEST_HOME}/opa/bundle.tar.gz'); printf '\\377' | dd of='${TBP_DEVTEST_HOME}/opa/bundle.tar.gz' bs=1 seek=\$((size / 2)) conv=notrunc 2>/dev/null"
file_attack "another verification key" "${TBP_DEVTEST_HOME}/opa/policy-verify.pub" opa.log "failed to verify JWT signature" \
  "openssl genrsa 2048 2>/dev/null | openssl rsa -pubout -out '${TBP_DEVTEST_HOME}/opa/policy-verify.pub' 2>/dev/null"
"${DEVTEST}" down >/dev/null 2>&1
if "${DEVTEST}" up >/dev/null 2>&1 && "${DEVTEST}" demo >/dev/null 2>&1; then ok "originals restored: it starts and the demo passes again"; else bad "originals restored but the cell does not start"; fi

echo "== report: numbers for the issue, and nothing secret in them"
"${DEVTEST}" report >"${WORK}/report.md" 2>&1
for needle in "commit:" "system:" "init:" "demo: 12/12" "broker counters" "refusal path, 50 requests" "p95"; do
  if grep -qF -- "${needle}" "${WORK}/report.md"; then ok "report has '${needle}'"; else bad "report lacks '${needle}'"; fi
done
leak=0
for secret in "${TBP_DEVTEST_HOME}" "$(cat "${TBP_DEVTEST_HOME}/issuer.seed")" "$(jq -r '.[0].key' "${TBP_DEVTEST_HOME}/operators.json")" "$(jq -r '.pubkeys[0]' "${TBP_DEVTEST_HOME}/genesis/manifest.json")" "$(hostname)"; do
  [ -n "${secret}" ] || continue
  if grep -qF -- "${secret}" "${WORK}/report.md"; then leak=1; echo "      the report contains: ${secret:0:12}…"; fi
done
if grep -qE '/(home|tmp|root|var|etc)/' "${WORK}/report.md"; then leak=1; echo "      the report contains a path"; fi
if [ "${leak}" -eq 0 ]; then ok "the report holds no key, seed, path or host name"; else bad "the report leaks something"; fi

echo "== the solo page (both languages) still names what the attempts above return"
for kw in "duplicate-key" "unknown-field" "body-unreadable" "quorum-required" "DIFFÉRENT" "agent-registry" "quorum-settings" "load error: bundle" "failed to verify JWT signature" "devtest.sh report" "SECURITY.md"; do
  for lang in solo.md solo.fr.md; do
    if grep -qF -- "${kw}" "${SCRIPT_DIR}/../../deploy/dev-test/${lang}"; then :; else bad "deploy/dev-test/${lang} no longer mentions '${kw}'"; fi
  done
done
# the page must keep saying what it does not test yet, in each language
for kw in "nothing checks them here" "site.md"; do
  grep -qF -- "${kw}" "${SCRIPT_DIR}/../../deploy/dev-test/solo.md" || bad "deploy/dev-test/solo.md no longer says '${kw}'"
done
for kw in "personne ne les vérifie ici" "site.fr.md"; do
  grep -qF -- "${kw}" "${SCRIPT_DIR}/../../deploy/dev-test/solo.fr.md" || bad "deploy/dev-test/solo.fr.md ne dit plus '${kw}'"
done
ok "deploy/dev-test/solo.md and solo.fr.md name every documented answer, and what is not tested here"

echo "== reset"
"${DEVTEST}" down >/dev/null 2>&1
"${DEVTEST}" reset -y >/dev/null 2>&1
if [ ! -e "${TBP_DEVTEST_HOME}" ]; then ok "reset deletes the home"; else bad "reset left ${TBP_DEVTEST_HOME}"; fi
if [ "${SENTINEL_BEFORE}" -eq 0 ]; then
  if [ ! -e "${SENTINEL}" ]; then ok "reset removes the sentinel it made"; else bad "reset left the sentinel it made"; fi
else
  echo "  skip - the sentinel was there before this test: reset must leave it"
  if [ -e "${SENTINEL}" ]; then ok "reset leaves a sentinel it did not make"; else bad "reset removed a sentinel it did not make"; fi
fi

echo "== machine that looks like production"
# the marker is checked by init: a directory named like a real deployment's is enough
if [ -e /var/lib/tbp ]; then
  echo "  skip - /var/lib/tbp exists here"
elif [ -w /var/lib ] || sudo -n true 2>/dev/null; then
  if [ -w /var/lib ]; then mkdir /var/lib/tbp; else sudo mkdir /var/lib/tbp; fi
  refuses "a machine with /var/lib/tbp is refused" "looks like it holds a real TBP deployment" "${DEVTEST}" init
  if [ -w /var/lib ]; then rmdir /var/lib/tbp; else sudo rmdir /var/lib/tbp; fi
else
  echo "  skip - cannot create /var/lib/tbp here"
fi

echo
if [ "${FAILS}" -eq 0 ]; then echo "test_devtest: all good"; else echo "test_devtest: ${FAILS} failure(s)"; exit 1; fi
