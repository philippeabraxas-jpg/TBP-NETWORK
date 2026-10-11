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
cp -- "$(command -v true)" "${FAKEBIN}/brokerd" 2>/dev/null || :
cp -- "$(command -v true)" "${FAKEBIN}/tbp-audit" 2>/dev/null || :
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
if "${DEVTEST}" up >"${WORK}/up.log" 2>&1; then ok "up"; else bad "up: $(tail -3 "${WORK}/up.log" | tr '\n' ' ')"; fi
if "${DEVTEST}" status >/dev/null 2>&1; then ok "status"; else bad "status"; fi
refuses "up while running is refused" "already running" "${DEVTEST}" up
if "${DEVTEST}" demo >"${WORK}/demo.log" 2>&1; then ok "demo"; else bad "demo: $(grep -E 'FAIL|expected' "${WORK}/demo.log" | tr '\n' ' ')"; fi
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
if grep -q "quorum-settings" "${TBP_DEVTEST_HOME}/log/brokerd.log"; then ok "brokerd names quorum-settings"; else bad "brokerd did not name quorum-settings"; fi
"${DEVTEST}" down >/dev/null 2>&1
cp -- "${WORK}/brokerd.env.orig" "${TBP_DEVTEST_HOME}/brokerd.env"
if "${DEVTEST}" up >/dev/null 2>&1 && "${DEVTEST}" demo >/dev/null 2>&1; then ok "restored, it starts and the demo passes again"; else bad "restored environment does not start"; fi

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
