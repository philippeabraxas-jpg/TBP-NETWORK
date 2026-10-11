#!/usr/bin/env bash
# scripts/devtest/site.sh — a three-machine DEV-TEST site: M1 the cell, M2 an application server, M3 an agent.
#
#   scripts/devtest/site.sh m1 init --address <M1 address> [--listen <addr:port>] [--env <label>]
#   scripts/devtest/site.sh m1 up | down | status | grant | mode-proof | pack | report | reset
#   scripts/devtest/site.sh m2 init --pack m2.pack.tgz --listen <addr:port> [--env <label>]
#   scripts/devtest/site.sh m2 up | down | status | mode | report | reset
#   scripts/devtest/site.sh m3 init --pack m3.pack.tgz --app http://<M2 address:port> [--env <label>]
#   scripts/devtest/site.sh m3 check | act | call | report | reset
#   scripts/devtest/site.sh <role> listeners       # what this machine listens on, to check the exposure
#
# ⚠ NOT FOR PRODUCTION. Throw-away keys, a seed-file issuer key on M1, no HSM, no real people behind the roles.
# What it is for: run the real binaries across three machines and test that the whole thing WORKS — an agent
# enrolled by certificate, a decision by the cell, a token checked by the enforcement point on a server — and attack it.
#
#   M1  the cell:    OPA + brokerd, an mTLS listener for agents, the keys of controllers and operators (the
#                    administration is done here, locally). Makes two packs for M2 and M3.
#   M2  the server:  OPA + pepd + a small application that asks pepd before it acts. Never holds a governance key.
#   M3  the agent:   curl and the certificates M1 issued. Asks M1 for a decision, then presents the token to M2.
#
# Documentation, the exact procedure and the roles: deploy/dev-test/site.md
#
# Needs — M1: opa, openssl, jq, curl, and `go` or built binaries in dist/ · M2: python3, curl, jq, openssl ·
# M3: curl, jq, perl, base64. A normal user on a clean Debian 12 machine; M1 uses `sudo` once, for the sentinel.
#
# Environment: TBP_SITE_HOME (default $HOME/tbp-site-<role>), OPA_BIN, DEVTEST_BIN_DIR (default dist),
# DEVTEST_ENV (a free label for your environment, repeated in `report`), DEVTEST_ALLOW_ROOT=1 (throw-away containers).

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)

ROLE=${1:-}
CMD=${2:-}
[ $# -ge 2 ] && shift 2 || shift $#

OPA_BIN=${OPA_BIN:-opa}
SRC_BIN_DIR=${DEVTEST_BIN_DIR:-"${REPO_ROOT}/dist"}
SENTINEL=/etc/tbp/DEV_ENVIRONMENT # fixed path, hard-coded in the binaries (#113)
CELL_ID=cell-site

HOME_DIR=${TBP_SITE_HOME:-"${HOME}/tbp-site-${ROLE:-x}"}
BIN_DIR="${HOME_DIR}/bin"
OPA_DIR="${HOME_DIR}/opa"
KEYS_DIR="${HOME_DIR}/keys"
GENESIS_DIR="${HOME_DIR}/genesis"
PKI_DIR="${HOME_DIR}/pki"
PACK_DIR="${HOME_DIR}/packs"
RUN_DIR="${HOME_DIR}/run"
LOG_DIR="${HOME_DIR}/log"
STATE_DIR="${HOME_DIR}/state"
OPA_SOCK="${RUN_DIR}/opa.sock"
BROKER_SOCK="${RUN_DIR}/broker.sock"
ADMIN_SOCK="${RUN_DIR}/broker-admin.sock"
PEPD_ADMIN_SOCK="${RUN_DIR}/pepd-admin.sock"
PEPD_ADDR=127.0.0.1:8443 # pepd's data plane: loopback only, the application on the same machine calls it
ENV_FILE="${HOME_DIR}/${ROLE:-x}.env"
LAUNCH_CONF="${OPA_DIR}/opa-launch.conf"

banner() {
  cat <<EOF
================================================================================
  TBP DEV-TEST SITE, machine ${ROLE^^} — NOT FOR PRODUCTION
  Throw-away keys. No real data, no real agents. Read deploy/dev-test/site.md.
================================================================================
EOF
}

die() { echo "site: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing prerequisite: $1 ($2)"; }
usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

# --- shared helpers ---------------------------------------------------------------------------------

# pid_of NAME: the pid in the pidfile when it still names a live process of that program (the process writes its
# own pid, then execs the program: for a few milliseconds its name is the launcher's).
pid_of() {
  local f="${RUN_DIR}/$1.pid" pid comm
  [ -s "$f" ] || return 0
  pid=$(cat "$f" 2>/dev/null || true)
  [ -n "$pid" ] || return 0
  comm=$(ps -p "$pid" -o comm= 2>/dev/null || true)
  case "${comm}" in "$1" | bash | sh | setsid | nohup | python3) echo "$pid" ;; esac
}

stop_one() {
  local name=$1 pid i
  pid=$(pid_of "$name")
  [ -n "$pid" ] || { rm -f "${RUN_DIR}/${name}.pid"; return 0; }
  kill "$pid" 2>/dev/null || true
  for i in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  rm -f "${RUN_DIR}/${name}.pid"
}

# start_bg NAME COMMAND... : detached; the child writes its OWN pid, then execs.
start_bg() {
  local name=$1 i
  shift
  rm -f "${RUN_DIR}/${name}.pid"
  setsid nohup bash -c 'echo $$ >"$1"; shift; exec "$@"' _ "${RUN_DIR}/${name}.pid" "$@" >"${LOG_DIR}/${name}.log" 2>&1 </dev/null &
  for i in $(seq 1 50); do [ -s "${RUN_DIR}/${name}.pid" ] && return 0; sleep 0.1; done
  die "${name}: did not start (no pid written)"
}

# wait_for NAME SECONDS DESCRIPTION COMMAND... : until COMMAND succeeds; at once if NAME died
wait_for() {
  local name=$1 secs=$2 what=$3 i
  shift 3
  for i in $(seq 1 $((secs * 10))); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    if [ -z "$(pid_of "${name}")" ]; then
      echo "--- last lines of ${LOG_DIR}/${name}.log" >&2
      tail -n 5 "${LOG_DIR}/${name}.log" >&2 || true
      die "${what}: ${name} exited at start"
    fi
    sleep 0.1
  done
  die "${what}: no answer after ${secs}s — see ${LOG_DIR}/"
}

require_init() { [ -f "${HOME_DIR}/SITE" ] || die "not initialised: run '$0 ${ROLE} init …' first (home: ${HOME_DIR})"; }

refuse_real_deployment() {
  local marker
  for marker in /var/lib/tbp /etc/tbp/brokerd.env /etc/tbp/pepd.env /etc/tbp/quorum-keyring.json; do
    [ ! -e "${marker}" ] || die "${marker} exists: this machine looks like it holds a real TBP deployment. Use a clean machine."
  done
}

refuse_root() {
  if [ "$(id -u)" -eq 0 ] && [ "${DEVTEST_ALLOW_ROOT:-}" != "1" ]; then
    die "do not run as root: use a normal user. In a throw-away container, DEVTEST_ALLOW_ROOT=1 allows it."
  fi
}

check_home_free() {
  [ ! -e "${HOME_DIR}" ] || [ -z "$(ls -A "${HOME_DIR}" 2>/dev/null)" ] ||
    die "${HOME_DIR} already exists: use it, or '$0 ${ROLE} reset' to start over"
  [ "${#RUN_DIR}" -le 80 ] || die "TBP_SITE_HOME is too long for Unix socket paths (${#RUN_DIR} chars, max 80): use a shorter one"
}

# begin_home / end_home: a failed init leaves nothing behind
SITE_CREATED=0
begin_home() {
  trap 'if [ "${SITE_CREATED}" -eq 1 ]; then echo "site: init failed — removing ${HOME_DIR}" >&2; rm -rf -- "${HOME_DIR}"; fi' EXIT
  umask 077
  mkdir -p "${HOME_DIR}" "${RUN_DIR}" "${LOG_DIR}" "${STATE_DIR}" "${BIN_DIR}"
  SITE_CREATED=1
}
end_home() { SITE_CREATED=0; trap - EXIT; }

set_env_label() { # set_env_label LABEL: a free text the tester gives, kept for the report
  local label=${1:-${DEVTEST_ENV:-}}
  [ "${#label}" -le 80 ] || die "--env label too long (max 80 characters)"
  printf '%s\n' "${label:-not given}" >"${STATE_DIR}/env-label"
}

percentile() { sort -n | awk -v p="$1" '{a[NR]=$1} END {i=int((p/100)*NR+0.999999); if (i<1) i=1; if (i>NR) i=NR; printf "%.1f", a[i]*1000}'; }

sysinfo_lines() {
  local os cpus mem
  os=$(sed -n 's/^PRETTY_NAME="\(.*\)"/\1/p' /etc/os-release 2>/dev/null || true)
  cpus=$(nproc 2>/dev/null || echo "?")
  mem=$(awk '/^MemTotal/ {printf "%d MiB", $2/1024}' /proc/meminfo 2>/dev/null || echo "?")
  echo "- machine: ${ROLE^^}"
  echo "- environment: $(cat "${STATE_DIR}/env-label" 2>/dev/null || echo "not given")"
  echo "- system: ${os:-unknown}, kernel $(uname -r), ${cpus} CPU, ${mem}"
}

commit_line() {
  local commit="unknown"
  if git -C "${REPO_ROOT}" rev-parse --short=12 HEAD >/dev/null 2>&1; then
    commit=$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)
    git -C "${REPO_ROOT}" diff --quiet 2>/dev/null || commit="${commit} (modified)"
  fi
  echo "- commit: ${commit}"
}

cmd_listeners() {
  echo "TCP sockets this machine listens on (address:port):"
  local f line state local_addr hex port ip a b c d
  for f in /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    while read -r _ local_addr _ state _; do
      [ "${state}" = "0A" ] || continue # LISTEN
      hex=${local_addr%:*}
      port=$((16#${local_addr#*:}))
      if [ "${#hex}" -eq 8 ]; then # IPv4, little-endian hex
        a=$((16#${hex:6:2})); b=$((16#${hex:4:2})); c=$((16#${hex:2:2})); d=$((16#${hex:0:2}))
        ip="${a}.${b}.${c}.${d}"
      elif [ "${hex}" = "00000000000000000000000000000000" ]; then ip="[::]"
      elif [ "${hex}" = "00000000000000000000000001000000" ]; then ip="[::1]"
      else ip="[ipv6]"; fi
      echo "  ${ip}:${port}"
    done < <(tail -n +2 "$f")
  done | sort -u
}

keygen() { # keygen KEYFILE KEYRING -> prints the public key (64 hex)
  local out pub
  out=$("${BIN_DIR}/quorumproof" keygen -key "$1" -keyring "$2") || die "quorumproof keygen failed for $1"
  pub=$(printf '%s\n' "$out" | tr ' ' '\n' | sed -n 's/^public=//p' | head -1)
  [ "${#pub}" -eq 64 ] || die "quorumproof keygen printed no public key: ${out}"
  printf '%s' "$pub"
}

write_opa_launch() { # the arguments `up` runs; brokerd/pepd measure this file as the OPA configuration
  {
    echo "run"; echo "--server"; echo "--addr"; echo "unix://${OPA_SOCK}"
    echo "--bundle"; echo "${OPA_DIR}/bundle.tar.gz"
    echo "--verification-key"; echo "${OPA_DIR}/policy-verify.pub"
    echo "--verification-key-id"; echo "default"
  } >"${LAUNCH_CONF}"
}

start_opa() {
  local opa_args=()
  mapfile -t opa_args <"${LAUNCH_CONF}"
  rm -f "${OPA_SOCK}"
  start_bg opa "${BIN_DIR}/opa" "${opa_args[@]}"
  wait_for opa 20 "opa health (bundle signature verified)" curl -fsS --unix-socket "${OPA_SOCK}" http://localhost/health
}

# ===================================================================================================
# M1 — the cell
# ===================================================================================================

m1_install_binaries() {
  local b pkg
  for b in brokerd quorumproof tbp-audit pepd; do
    if [ -x "${SRC_BIN_DIR}/${b}" ]; then
      cp -- "${SRC_BIN_DIR}/${b}" "${BIN_DIR}/${b}"
    else
      need go "or build the release binaries first: bash scripts/release/build.sh dist"
      case "$b" in
        brokerd) pkg=./src/broker/cmd/brokerd ;;
        quorumproof) pkg=./src/pep/cmd/quorumproof ;;
        tbp-audit) pkg=./src/registry/cmd/tbp-audit ;;
        pepd) pkg=./src/pep/cmd/pepd ;;
      esac
      (cd "${REPO_ROOT}" && go build -o "${BIN_DIR}/${b}" "${pkg}")
    fi
  done
  # a real copy (not a link): it goes into the pack for M2, and the process-name check of `down` relies on the name
  cp -- "$(command -v "${OPA_BIN}")" "${BIN_DIR}/opa"
}

m1_write_sentinel() {
  [ ! -e "${SENTINEL}" ] || return 0
  local content="DEV-TEST site, machine M1, made by scripts/devtest/site.sh. Remove with: scripts/devtest/site.sh m1 reset"
  if [ -w "$(dirname "${SENTINEL}")" ] 2>/dev/null; then
    printf '%s\n' "${content}" >"${SENTINEL}"
  elif command -v sudo >/dev/null 2>&1; then
    sudo install -d -m 0755 "$(dirname "${SENTINEL}")"
    printf '%s\n' "${content}" | sudo tee "${SENTINEL}" >/dev/null
  else
    die "cannot write ${SENTINEL} (no write access, no sudo). brokerd refuses a seed-file issuer key without it."
  fi
  : >"${STATE_DIR}/sentinel-created-by-site"
}

mk_ca() { # mk_ca NAME COMMON-NAME
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "${PKI_DIR}/$1.key" \
    -out "${PKI_DIR}/$1.pem" -subj "/CN=$2" -days 30 2>/dev/null
}
mk_leaf() { # mk_leaf CA NAME COMMON-NAME EXTENSIONS
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "${PKI_DIR}/$2.key" \
    -out "${PKI_DIR}/$2.csr" -subj "/CN=$3" 2>/dev/null
  printf '%s\n' "$4" >"${PKI_DIR}/$2.ext"
  openssl x509 -req -in "${PKI_DIR}/$2.csr" -CA "${PKI_DIR}/$1.pem" -CAkey "${PKI_DIR}/$1.key" -CAcreateserial \
    -out "${PKI_DIR}/$2.pem" -days 30 -extfile "${PKI_DIR}/$2.ext" 2>/dev/null
  rm -f "${PKI_DIR}/$2.csr" "${PKI_DIR}/$2.ext"
}

m1_make_packs() {
  [ -f "${HOME_DIR}/SITE" ] || die "not initialised"
  local policy_id addr broker_url w
  policy_id=$(sed -n 's/^TBP_POLICY_ID=//p' "${ENV_FILE}")
  broker_url=$(cat "${STATE_DIR}/broker-url")
  mkdir -p "${PACK_DIR}"
  w=$(mktemp -d "${STATE_DIR}/pack.XXXXXX")

  # M2: what an application server needs to check tokens — public material and binaries, no governance key
  mkdir -p "${w}/m2/bin"
  cp -- "${BIN_DIR}/pepd" "${BIN_DIR}/tbp-audit" "${BIN_DIR}/opa" "${w}/m2/bin/"
  cp -- "${OPA_DIR}/bundle.tar.gz" "${OPA_DIR}/policy-verify.pub" "${w}/m2/"
  cp -- "${HOME_DIR}/issuer-keyring.json" "${w}/m2/issuer-keyring.json"
  cp -- "${KEYS_DIR}/quorum-keyring.json" "${w}/m2/quorum-keyring.json"
  printf 'CELL_ID=%s\nPOLICY_ID=%s\n' "${CELL_ID}" "${policy_id}" >"${w}/m2/site.env"
  tar -C "${w}/m2" -czf "${PACK_DIR}/m2.pack.tgz" .

  # M3: the agents' certificates and what verifies the cell. The agents' PRIVATE keys are in it: it goes to M3 only.
  mkdir -p "${w}/m3/agents"
  cp -- "${PKI_DIR}/server-ca.pem" "${w}/m3/server-ca.pem"
  for addr in agent-f agent-i agent-w; do cp -- "${PKI_DIR}/${addr}.pem" "${PKI_DIR}/${addr}.key" "${w}/m3/agents/"; done
  printf 'CELL_ID=%s\nBROKER_URL=%s\n' "${CELL_ID}" "${broker_url}" >"${w}/m3/site.env"
  tar -C "${w}/m3" -czf "${PACK_DIR}/m3.pack.tgz" .
  rm -rf -- "${w}"
  chmod 600 "${PACK_DIR}"/*.tgz
}

m1_init() {
  local t0=${SECONDS} address="" listen="" label=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --address) address=${2:-}; shift 2 ;;
      --listen) listen=${2:-}; shift 2 ;;
      --env) label=${2:-}; shift 2 ;;
      *) die "m1 init: unknown option $1" ;;
    esac
  done
  banner
  [ -n "${address}" ] || die "m1 init: --address is required: the address agents will use to reach this machine (its PRIVATE address on your network)"
  [ -n "${listen}" ] || listen="${address}:8443"
  case "${listen}" in *:*) ;; *) die "--listen must be addr:port" ;; esac
  case "${listen}" in 0.0.0.0:* | \[::\]:*) echo "site: WARNING: ${listen} listens on every interface, public ones included. Prefer this machine's private address." >&2 ;; esac
  check_home_free
  refuse_real_deployment
  need "${OPA_BIN}" "the Open Policy Agent binary, see deploy/dev-test/site.md"
  need openssl "apt install openssl"; need jq "apt install jq"; need curl "apt install curl"
  refuse_root

  begin_home
  mkdir -p "${OPA_DIR}" "${KEYS_DIR}" "${GENESIS_DIR}" "${PKI_DIR}" "${HOME_DIR}/registry" "${HOME_DIR}/audit"
  set_env_label "${label}"

  echo "== 1/7 binaries"
  m1_install_binaries

  echo "== 2/7 restricted OPA capabilities, signed rule bundle"
  (cd "${REPO_ROOT}" && PATH="${BIN_DIR}:${PATH}" sh policies/gen_capabilities.sh >"${LOG_DIR}/gen_capabilities.log") ||
    die "policies/gen_capabilities.sh failed — see ${LOG_DIR}/gen_capabilities.log"
  cp -- "${REPO_ROOT}/policies/capabilities.json" "${OPA_DIR}/capabilities.json"
  openssl genrsa -out "${OPA_DIR}/policy-signing.key" 2048 2>/dev/null
  openssl rsa -in "${OPA_DIR}/policy-signing.key" -pubout -out "${OPA_DIR}/policy-verify.pub" 2>/dev/null
  local policy_id
  policy_id=$(cd "${REPO_ROOT}" && sha256sum -- policies/rego/*.rego | sha256sum | cut -d' ' -f1)
  (cd "${REPO_ROOT}" && "${BIN_DIR}/opa" build --capabilities "${OPA_DIR}/capabilities.json" --revision "${policy_id}" \
    --signing-key "${OPA_DIR}/policy-signing.key" --signing-alg RS256 -b policies/rego/ -o "${OPA_DIR}/bundle.tar.gz")
  write_opa_launch

  echo "== 3/7 three controllers (k = 2 of 3), four operator keys with roles"
  local ctl=() op=() i
  for i in 1 2 3; do ctl+=("$(keygen "${KEYS_DIR}/controller-${i}.key" "${KEYS_DIR}/quorum-keyring.json")"); done
  printf '{"pubkeys":["%s","%s","%s"]}\n' "${ctl[0]}" "${ctl[1]}" "${ctl[2]}" >"${GENESIS_DIR}/manifest.json"
  for i in 1 2 3 4; do op+=("$(keygen "${KEYS_DIR}/operator-${i}.key" "${KEYS_DIR}/operator-${i}-ring.json")"); done
  jq -n --arg a "${op[0]}" --arg b "${op[1]}" --arg c "${op[2]}" --arg d "${op[3]}" \
    '[{key:$a,roles:["approve"]},{key:$b,roles:["approve"]},{key:$c,roles:["revoke","arbitrate"]},{key:$d,roles:["submit"]}]' \
    >"${HOME_DIR}/operators.json"

  echo "== 4/7 issuer key, agent registry"
  # the issuer key is made like a controller key: the public half is what M2's pepd pins to check tokens
  keygen "${HOME_DIR}/issuer.seed" "${HOME_DIR}/issuer-keyring.json" >/dev/null
  # every agent here is a NETWORK agent: bound to the CN of its certificate, refused on the local socket
  printf '{"agent-f":{"class":0,"transport_identity":"agent-f"},"agent-i":{"class":1,"transport_identity":"agent-i"},"agent-w":{"class":2,"transport_identity":"agent-w"}}\n' \
    >"${HOME_DIR}/agents.json"

  echo "== 5/7 certificates: a CA for the cell's server certificate, a CA dedicated to agent certificates"
  mk_ca server-ca "tbp-site-server-ca"
  local san
  if [[ "${address}" =~ ^[0-9.]+$ ]] || [[ "${address}" == *:* ]]; then san="IP:${address}"; else san="DNS:${address}"; fi
  mk_leaf server-ca broker-tls "tbp-site-brokerd" "subjectAltName=${san}
extendedKeyUsage=serverAuth"
  mk_ca agent-ca "tbp-site-agent-ca"
  for i in agent-f agent-i agent-w; do mk_leaf agent-ca "$i" "$i" "extendedKeyUsage=clientAuth"; done

  echo "== 6/7 brokerd environment"
  {
    echo "# DEV-TEST site, machine M1 — generated by scripts/devtest/site.sh. Not a production file."
    echo "TBP_CELL_ID=${CELL_ID}"
    echo "TBP_SALT=$(openssl rand -hex 16)"
    echo "TBP_POLICY_ID=${policy_id}"
    echo "TBP_REGISTRY_DIR=${HOME_DIR}/registry/${CELL_ID}"
    echo "TBP_AUDIT_RECORDS=${HOME_DIR}/audit/brokerd-records.jsonl"
    echo "TBP_AUDIT_RECORDS_KEY_FILE=${HOME_DIR}/brokerd-audit.key"
    echo "TBP_OPA_ENDPOINT=http://opa/v1/data/tbp/example/action"
    echo "TBP_OPA_SOCKET=${OPA_SOCK}"
    echo "TBP_OPA_EXPECTED_UID=$(id -u)"
    echo "TBP_TRANSLATOR=structured"
    echo "TBP_ISSUER_SEED_FILE=${HOME_DIR}/issuer.seed"
    echo "TBP_GENESIS_DIR=${GENESIS_DIR}"
    echo "TBP_QUORUM_MIN=2"
    echo "TBP_TOPOLOGY=mono"
    echo "TBP_CLUSTER_MEMBERS=${CELL_ID}"
    echo "TBP_OPERATOR_KEYS_FILE=${HOME_DIR}/operators.json"
    echo "TBP_AGENT_REGISTRY_FILE=${HOME_DIR}/agents.json"
    echo "TBP_PROVISIONING_WITNESS_FILE=${STATE_DIR}/brokerd-provisioning-witness.json"
    echo "TBP_PROVISIONING_POLICY_BUNDLE=${OPA_DIR}/bundle.tar.gz"
    echo "TBP_PROVISIONING_OPA_CONFIG=${LAUNCH_CONF}"
    echo "TBP_PROVISIONING_EXTRA_FILES=opa-verification-key=${OPA_DIR}/policy-verify.pub"
    echo "TBP_BROKER_SOCKET=${BROKER_SOCK}"
    echo "TBP_BROKER_ADMIN_SOCKET=${ADMIN_SOCK}"
    echo "TBP_BROKER_LISTEN_ADDR=${listen}"
    echo "TBP_BROKER_TLS_CERT_FILE=${PKI_DIR}/broker-tls.pem"
    echo "TBP_BROKER_TLS_KEY_FILE=${PKI_DIR}/broker-tls.key"
    echo "TBP_BROKER_TLS_CLIENT_CA_FILE=${PKI_DIR}/agent-ca.pem"
  } >"${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
  "${BIN_DIR}/tbp-audit" keygen -out "${HOME_DIR}/brokerd-audit.key" >/dev/null
  printf 'https://%s\n' "${address}:${listen##*:}" >"${STATE_DIR}/broker-url"

  echo "== 7/7 development sentinel (${SENTINEL}) and the packs for M2 and M3"
  m1_write_sentinel
  printf 'site M1\ncell: %s\n' "${CELL_ID}" >"${HOME_DIR}/SITE"
  m1_make_packs
  echo $((SECONDS - t0)) >"${STATE_DIR}/init-seconds"
  end_home
  echo
  echo "site M1: initialised in ${HOME_DIR}. Next: $0 m1 up, then copy the packs:"
  echo "    scp ${PACK_DIR}/m2.pack.tgz <user>@<M2>:   (public material and binaries; no governance key)"
  echo "    scp ${PACK_DIR}/m3.pack.tgz <user>@<M3>:   (the agents' private keys: M3 only)"
}

m1_up() {
  local t0=${SECONDS}
  banner
  require_init
  [ -e "${SENTINEL}" ] || die "${SENTINEL} is missing: brokerd would refuse its seed-file issuer key."
  [ -z "$(pid_of opa)" ] && [ -z "$(pid_of brokerd)" ] || die "already running: '$0 m1 status', or '$0 m1 down' first"
  rm -f "${BROKER_SOCK}" "${ADMIN_SOCK}"
  trap 'stop_one brokerd; stop_one opa' EXIT
  start_opa
  start_bg brokerd bash -c 'set -a; . "$1"; set +a; exec "$2"' _ "${ENV_FILE}" "${BIN_DIR}/brokerd"
  wait_for brokerd 30 "brokerd stats" curl -fsS --unix-socket "${ADMIN_SOCK}" http://localhost/v1/supervision/stats
  if grep -q "AVERTISSEMENT quorum" "${LOG_DIR}/brokerd.log"; then die "brokerd warns about a fragile quorum — see ${LOG_DIR}/brokerd.log"; fi
  trap - EXIT
  echo $((SECONDS - t0)) >"${STATE_DIR}/up-seconds"
  echo "site M1: up. Agents reach the cell at $(cat "${STATE_DIR}/broker-url") (mutual TLS)."
  echo "         expected in ${LOG_DIR}/brokerd.log: a high-priority alarm that a development environment is declared."
}

m1_down() { stop_one brokerd; stop_one opa; rm -f "${OPA_SOCK}" "${BROKER_SOCK}" "${ADMIN_SOCK}"; echo "site M1: down"; }

m1_status() {
  require_init
  local rc=0
  printf 'opa      : '; if [ -n "$(pid_of opa)" ] && curl -fsS --unix-socket "${OPA_SOCK}" http://localhost/health >/dev/null 2>&1; then echo up; else echo DOWN; rc=1; fi
  printf 'brokerd  : '; if [ -n "$(pid_of brokerd)" ] && curl -fsS --unix-socket "${ADMIN_SOCK}" http://localhost/v1/supervision/stats >/dev/null 2>&1; then echo up; else echo DOWN; rc=1; fi
  [ "${rc}" -ne 0 ] || echo "counters : $(curl -fsS --unix-socket "${ADMIN_SOCK}" http://localhost/v1/supervision/stats)"
  return "${rc}"
}

# m1_grant AGENT ACTION RESOURCE: what the operators and controllers do for ONE action of an agent — a signed plan,
# approved by as many operators as the agent's class needs and, for class W, a proof signed by two controllers.
m1_grant() {
  require_init
  [ $# -eq 3 ] || die "usage: $0 m1 grant <agent> <action> <resource>"
  local agent=$1 action=$2 resource=$3 class w hash binding proof="" exp keys=()
  class=$(jq -r --arg a "${agent}" '.[$a].class // empty' "${HOME_DIR}/agents.json")
  [ -n "${class}" ] || die "unknown agent ${agent} (agent-f, agent-i, agent-w)"
  m1_status >/dev/null 2>&1 || die "the cell is not running: '$0 m1 up' first"
  w=$(mktemp -d "${STATE_DIR}/grant.XXXXXX")
  # shellcheck disable=SC2064
  trap "rm -rf -- '${w}'" EXIT
  jq -cn --arg s "${agent}" --arg a "${action}" --arg r "${resource}" '{subject:$s,steps:[{action:$a,resource:$r,params_hex:""}]}' >"${w}/plan.json"
  "${BIN_DIR}/quorumproof" plansubmit -cell "${CELL_ID}" -plan "${w}/plan.json" -key "${KEYS_DIR}/operator-4.key" -out "${w}/sub.json" >/dev/null 2>&1
  hash=$(curl -fsS --unix-socket "${ADMIN_SOCK}" -X POST -d @"${w}/sub.json" http://localhost/v1/supervision/plan/submit | jq -r .plan_hash)
  [ "${#hash}" -eq 64 ] || die "the cell did not accept the plan"
  exp=$(date -u -d '+30 minutes' +%Y-%m-%dT%H:%M:%SZ)
  keys=(-key "${KEYS_DIR}/operator-1.key")
  [ "${class}" = "1" ] || keys+=(-key "${KEYS_DIR}/operator-2.key") # class F and W: k distinct approvers
  "${BIN_DIR}/quorumproof" planapprove -plan-hash "${hash}" -expires-at "${exp}" "${keys[@]}" -out "${w}/appr.json" >/dev/null 2>&1
  curl -fsS --unix-socket "${ADMIN_SOCK}" -X POST -d @"${w}/appr.json" http://localhost/v1/supervision/plan/approve >/dev/null ||
    die "the cell refused the approval"
  binding=$("${BIN_DIR}/quorumproof" planbind -plan-hash "${hash}")
  if [ "${class}" = "2" ]; then
    "${BIN_DIR}/quorumproof" wproof -manifest "${GENESIS_DIR}/manifest.json" -action "${action}" -resource "${resource}" \
      -policy "$(sed -n 's/^TBP_POLICY_ID=//p' "${ENV_FILE}")" -key "${KEYS_DIR}/controller-1.key" -key "${KEYS_DIR}/controller-3.key" \
      -out "${w}/proof.json" >/dev/null 2>&1
    proof=$(od -An -v -tx1 "${w}/proof.json" | tr -d ' \n')
  fi
  echo "plan approved for ${agent} to ${action} ${resource} (class ${class}); valid 30 minutes. On M3, within the next 4 minutes:"
  echo
  if [ -n "${proof}" ]; then
    echo "    scripts/devtest/site.sh m3 act ${agent} ${action} ${resource} --binding ${binding} --proof ${proof}"
  else
    echo "    scripts/devtest/site.sh m3 act ${agent} ${action} ${resource} --binding ${binding}"
  fi
  echo
}

# m1_mode_proof closed|monitor [--controllers N]: the controllers' signature for pepd on M2. Closing restricts, so ONE
# controller is enough by default; reopening (monitor) widens, so it takes TWO.
m1_mode_proof() {
  require_init
  local mode=${1:-} n="" out
  shift || true
  while [ $# -gt 0 ]; do case "$1" in --controllers) n=${2:-}; shift 2 ;; *) die "mode-proof: unknown option $1" ;; esac; done
  case "${mode}" in closed) n=${n:-1} ;; monitor) n=${n:-2} ;; *) die "usage: $0 m1 mode-proof closed|monitor [--controllers N]" ;; esac
  local keys=() i
  for i in $(seq 1 "${n}"); do keys+=(-key "${KEYS_DIR}/controller-$((i == 2 ? 3 : i)).key"); done # 1, then 3 (as if 2 were away)
  mkdir -p "${HOME_DIR}/proofs"
  out="${HOME_DIR}/proofs/mode-${mode}-${n}sig-$(date +%s).json"
  "${BIN_DIR}/quorumproof" sign -condition "mode-${mode}" -cell "${CELL_ID}" "${keys[@]}" -out "${out}.raw" >/dev/null 2>&1 || die "quorumproof sign failed"
  jq --arg m "${mode}" '. + {mode:$m}' "${out}.raw" >"${out}" && rm -f "${out}.raw"
  echo "proof for pepd: ${out}   (${n} controller signature(s); valid about 4 minutes)"
  echo "    scp ${out} <user>@<M2>:   then on M2:  $0 m2 mode ${mode} --proof $(basename "${out}")"
}

m1_report() {
  require_init
  echo "### TBP dev-test report — M1 (the cell)"
  echo
  commit_line
  sysinfo_lines
  echo "- opa: $("${BIN_DIR}/opa" version 2>/dev/null | sed -n 's/^Version: //p' | head -1); go: $(go version 2>/dev/null | awk '{print $3}' || true)"
  echo "- init: $(cat "${STATE_DIR}/init-seconds" 2>/dev/null || echo "?") s; up: $(cat "${STATE_DIR}/up-seconds" 2>/dev/null || echo "?") s"
  if m1_status >/dev/null 2>&1; then
    echo "- broker counters: $(curl -fsS --unix-socket "${ADMIN_SOCK}" http://localhost/v1/supervision/stats)"
  else
    echo "- the cell is not running: counters not read"
  fi
  echo "- what I tried and what happened: (write here)"
  echo "- where I got stuck: (write here)"
}

m1_reset() {
  local yes=0
  [ "${1:-}" != "-y" ] || yes=1
  if [ -e "${HOME_DIR}" ] && [ ! -f "${HOME_DIR}/SITE" ]; then die "${HOME_DIR} exists but is not a site home (no SITE marker): refusing to delete it"; fi
  if [ "${yes}" -eq 0 ]; then
    printf 'This stops the cell and DELETES %s (all keys, packs and the registry). Type "reset" to go on: ' "${HOME_DIR}"
    read -r answer
    [ "${answer}" = "reset" ] || die "cancelled"
  fi
  [ ! -d "${RUN_DIR}" ] || m1_down >/dev/null
  local made=0
  [ -f "${STATE_DIR}/sentinel-created-by-site" ] && made=1
  rm -rf -- "${HOME_DIR}"
  if [ "${made}" -eq 1 ] && [ -e "${SENTINEL}" ]; then
    if [ -w "$(dirname "${SENTINEL}")" ]; then rm -f "${SENTINEL}"; else sudo rm -f "${SENTINEL}" || echo "site: remove ${SENTINEL} by hand" >&2; fi
  fi
  echo "site M1: reset"
}

# ===================================================================================================
# M2 — the application server: OPA + pepd + the application
# ===================================================================================================

m2_init() {
  local t0=${SECONDS} pack="" listen="" label=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --pack) pack=${2:-}; shift 2 ;;
      --listen) listen=${2:-}; shift 2 ;;
      --env) label=${2:-}; shift 2 ;;
      *) die "m2 init: unknown option $1" ;;
    esac
  done
  banner
  [ -f "${pack}" ] || die "m2 init: --pack <m2.pack.tgz> (the file M1 made, copied here)"
  [ -n "${listen}" ] || die "m2 init: --listen <addr:port>: where the application listens for agents (this machine's PRIVATE address, port 9000)"
  case "${listen}" in *:*) ;; *) die "--listen must be addr:port" ;; esac
  case "${listen}" in 0.0.0.0:* | \[::\]:*) echo "site: WARNING: ${listen} listens on every interface, public ones included. Prefer this machine's private address." >&2 ;; esac
  check_home_free
  refuse_real_deployment
  need python3 "apt install python3"; need curl "apt install curl"; need jq "apt install jq"; need openssl "apt install openssl"
  refuse_root

  begin_home
  mkdir -p "${OPA_DIR}" "${HOME_DIR}/registry" "${HOME_DIR}/audit" "${HOME_DIR}/app"
  set_env_label "${label}"
  local w
  w=$(mktemp -d "${STATE_DIR}/pack.XXXXXX")
  tar -C "${w}" -xzf "${pack}" || die "cannot unpack ${pack}"
  for f in bin/pepd bin/tbp-audit bin/opa bundle.tar.gz policy-verify.pub issuer-keyring.json quorum-keyring.json site.env; do
    [ -f "${w}/${f}" ] || die "the pack lacks ${f}: is it M1's m2.pack.tgz?"
  done
  cp -- "${w}/bin/pepd" "${w}/bin/tbp-audit" "${w}/bin/opa" "${BIN_DIR}/"
  chmod +x "${BIN_DIR}"/*
  cp -- "${w}/bundle.tar.gz" "${w}/policy-verify.pub" "${OPA_DIR}/"
  cp -- "${w}/issuer-keyring.json" "${w}/quorum-keyring.json" "${HOME_DIR}/"
  local cell policy
  cell=$(sed -n 's/^CELL_ID=//p' "${w}/site.env")
  policy=$(sed -n 's/^POLICY_ID=//p' "${w}/site.env")
  rm -rf -- "${w}"
  write_opa_launch
  cp -- "${SCRIPT_DIR}/site-app.py" "${HOME_DIR}/app/site-app.py"
  # measured boot measures four artifacts; this machine has no broker and no AI container, so two stand-ins
  # (the pepd binary, a placeholder file), recorded at the first start. The reference root is the dev-stub's.
  echo "stand-in for the AI container measured at boot (this machine runs none)" >"${HOME_DIR}/app/ai-container.txt"
  local root
  root=$(openssl rand -hex 32)
  echo "${root}" >"${HOME_DIR}/measured-root"
  "${BIN_DIR}/tbp-audit" keygen -out "${HOME_DIR}/pepd-audit.key" >/dev/null
  {
    echo "# DEV-TEST site, machine M2 — generated by scripts/devtest/site.sh. Not a production file."
    echo "TBP_CELL_ID=${cell}"
    echo "TBP_SALT=$(openssl rand -hex 16)"
    echo "TBP_KEYRING_FILE=${HOME_DIR}/issuer-keyring.json"
    echo "TBP_POLICY_ID=${policy}"
    echo "TBP_REGISTRY_DIR=${HOME_DIR}/registry/pepd"
    echo "TBP_AUDIT_RECORDS=${HOME_DIR}/audit/pepd-records.jsonl"
    echo "TBP_AUDIT_RECORDS_KEY_FILE=${HOME_DIR}/pepd-audit.key"
    echo "TBP_LISTEN_ADDR=${PEPD_ADDR}"
    echo "TBP_ADMIN_SOCKET=${PEPD_ADMIN_SOCK}"
    echo "TBP_OPA_ENDPOINT=http://opa/v1/data/tbp/example/action"
    echo "TBP_OPA_SOCKET=${OPA_SOCK}"
    echo "TBP_OPA_EXPECTED_UID=$(id -u)"
    echo "TBP_QUORUM_MIN=2"
    echo "TBP_QUORUM_KEYRING_FILE=${HOME_DIR}/quorum-keyring.json"
    echo "TBP_TOPOLOGY=mono"
    echo "TBP_PROVISIONING_WITNESS_FILE=${STATE_DIR}/pepd-provisioning-witness.json"
    echo "TBP_MEASURED_BOOT_MANIFEST_FILE=${STATE_DIR}/measured-boot.json"
    echo "TBP_MEASURED_BOOT_ROOT_FILE=${HOME_DIR}/measured-root"
    echo "TBP_MEASURED_BOOT_EXPECTED_ROOT=${root}"
    echo "TBP_MEASURED_BOOT_POLICY_BUNDLE=${OPA_DIR}/bundle.tar.gz"
    echo "TBP_MEASURED_BOOT_OPA_CONFIG=${LAUNCH_CONF}"
    echo "TBP_MEASURED_BOOT_BROKER_BINARY=${BIN_DIR}/pepd"
    echo "TBP_MEASURED_BOOT_AI_CONTAINER=${HOME_DIR}/app/ai-container.txt"
  } >"${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
  printf '%s\n' "${listen}" >"${STATE_DIR}/app-listen"
  printf 'site M2\ncell: %s\n' "${cell}" >"${HOME_DIR}/SITE"
  echo $((SECONDS - t0)) >"${STATE_DIR}/init-seconds"
  end_home
  echo "site M2: initialised in ${HOME_DIR}. Next: $0 m2 up"
}

pepd_mode() { curl -fsS --unix-socket "${PEPD_ADMIN_SOCK}" http://localhost/v1/mode 2>/dev/null | jq -r .mode 2>/dev/null; }

m2_up() {
  local t0=${SECONDS} mode
  banner
  require_init
  [ -z "$(pid_of opa)" ] && [ -z "$(pid_of pepd)" ] && [ -z "$(pid_of app)" ] || die "already running: '$0 m2 status', or '$0 m2 down' first"
  rm -f "${PEPD_ADMIN_SOCK}"
  trap 'stop_one app; stop_one pepd; stop_one opa' EXIT
  start_opa
  start_bg pepd bash -c 'set -a; . "$1"; set +a; exec "$2"' _ "${ENV_FILE}" "${BIN_DIR}/pepd"
  wait_for pepd 30 "pepd admin socket" curl -fsS --unix-socket "${PEPD_ADMIN_SOCK}" http://localhost/v1/mode
  APP_LISTEN=$(cat "${STATE_DIR}/app-listen") PEPD_URL="http://${PEPD_ADDR}" start_bg app python3 "${HOME_DIR}/app/site-app.py"
  wait_for app 10 "the application" curl -fsS "http://$(cat "${STATE_DIR}/app-listen")/healthz"
  trap - EXIT
  echo $((SECONDS - t0)) >"${STATE_DIR}/up-seconds"
  mode=$(pepd_mode)
  echo "site M2: up. The application listens on $(cat "${STATE_DIR}/app-listen"); pepd's posture: ${mode}."
  case "${mode}" in
    monitor) echo "         monitor: pepd records every verdict and blocks nothing. Closing is governed: $0 m1 mode-proof closed (on M1)." ;;
    refused) echo "         refused: after a restart pepd blocks everything until a quorum reconfirms a posture: $0 m1 mode-proof monitor (on M1), then $0 m2 mode monitor --proof <file>." ;;
  esac
}

m2_down() { stop_one app; stop_one pepd; stop_one opa; rm -f "${OPA_SOCK}" "${PEPD_ADMIN_SOCK}"; echo "site M2: down"; }

m2_status() {
  require_init
  local rc=0
  printf 'opa          : '; if [ -n "$(pid_of opa)" ] && curl -fsS --unix-socket "${OPA_SOCK}" http://localhost/health >/dev/null 2>&1; then echo up; else echo DOWN; rc=1; fi
  printf 'pepd         : '; if [ -n "$(pid_of pepd)" ] && [ -n "$(pepd_mode)" ]; then echo "up, posture $(pepd_mode)"; else echo DOWN; rc=1; fi
  printf 'application  : '; if [ -n "$(pid_of app)" ] && curl -fsS "http://$(cat "${STATE_DIR}/app-listen")/healthz" >/dev/null 2>&1; then echo "up on $(cat "${STATE_DIR}/app-listen")"; else echo DOWN; rc=1; fi
  return "${rc}"
}

# m2_mode closed|monitor --proof FILE: the controllers' proof, made on M1, posted to pepd's admin socket
m2_mode() {
  require_init
  local mode=${1:-} proof=""
  shift || true
  while [ $# -gt 0 ]; do case "$1" in --proof) proof=${2:-}; shift 2 ;; *) die "mode: unknown option $1" ;; esac; done
  case "${mode}" in closed | monitor) ;; *) die "usage: $0 m2 mode closed|monitor --proof <file from M1>" ;; esac
  [ -f "${proof}" ] || die "--proof <file>: the proof M1 made with '$0 m1 mode-proof ${mode}', copied here"
  [ "$(jq -r .mode "${proof}" 2>/dev/null)" = "${mode}" ] || die "this proof is not for '${mode}' (its mode: $(jq -r .mode "${proof}" 2>/dev/null))"
  curl -sS --unix-socket "${PEPD_ADMIN_SOCK}" -X POST -H 'Content-Type: application/json' -d @"${proof}" -w ' [%{http_code}]\n' http://localhost/v1/mode
}

m2_report() {
  require_init
  local n=30 i lat
  echo "### TBP dev-test report — M2 (the application server)"
  echo
  commit_line
  sysinfo_lines
  echo "- opa: $("${BIN_DIR}/opa" version 2>/dev/null | sed -n 's/^Version: //p' | head -1); python: $(python3 --version 2>/dev/null | awk '{print $2}')"
  echo "- init: $(cat "${STATE_DIR}/init-seconds" 2>/dev/null || echo "?") s; up: $(cat "${STATE_DIR}/up-seconds" 2>/dev/null || echo "?") s"
  if m2_status >/dev/null 2>&1; then
    echo "- pepd posture: $(pepd_mode)"
    echo "- pepd counters: $(curl -fsS --unix-socket "${PEPD_ADMIN_SOCK}" http://localhost/healthz | jq -c . 2>/dev/null || echo "?")"
    lat=$(mktemp "${STATE_DIR}/lat.XXXXXX")
    for i in $(seq 1 "${n}"); do
      curl -sS -o /dev/null -w '%{time_total}\n' -H 'X-TBP-Token: AAAA' "http://$(cat "${STATE_DIR}/app-listen")/read/doc-1" >>"${lat}"
    done
    echo "- application → pepd, a malformed token (the cheapest verdict), ${n} requests: p50 $(percentile 50 <"${lat}") ms, p95 $(percentile 95 <"${lat}") ms, max $(percentile 100 <"${lat}") ms"
    rm -f -- "${lat}"
  else
    echo "- the server is not running: counters and latency not measured"
  fi
  echo "- what I tried and what happened: (write here)"
  echo "- where I got stuck: (write here)"
}

m2_reset() {
  local yes=0
  [ "${1:-}" != "-y" ] || yes=1
  if [ -e "${HOME_DIR}" ] && [ ! -f "${HOME_DIR}/SITE" ]; then die "${HOME_DIR} exists but is not a site home (no SITE marker): refusing to delete it"; fi
  if [ "${yes}" -eq 0 ]; then
    printf 'This stops the server and DELETES %s. Type "reset" to go on: ' "${HOME_DIR}"
    read -r answer
    [ "${answer}" = "reset" ] || die "cancelled"
  fi
  [ ! -d "${RUN_DIR}" ] || m2_down >/dev/null
  rm -rf -- "${HOME_DIR}"
  echo "site M2: reset"
}

# ===================================================================================================
# M3 — the agent
# ===================================================================================================

m3_init() {
  local t0=${SECONDS} pack="" app="" label=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --pack) pack=${2:-}; shift 2 ;;
      --app) app=${2:-}; shift 2 ;;
      --env) label=${2:-}; shift 2 ;;
      *) die "m3 init: unknown option $1" ;;
    esac
  done
  banner
  [ -f "${pack}" ] || die "m3 init: --pack <m3.pack.tgz> (the file M1 made, copied here)"
  [ -n "${app}" ] || die "m3 init: --app http://<M2 address>:<port>: the application on M2"
  case "${app}" in http://*) ;; *) die "--app must look like http://addr:port" ;; esac
  check_home_free
  need curl "apt install curl"; need jq "apt install jq"; need perl "apt install perl"; need base64 "coreutils"
  refuse_root
  begin_home
  set_env_label "${label}"
  mkdir -p "${HOME_DIR}/agents"
  tar -C "${HOME_DIR}" -xzf "${pack}" || die "cannot unpack ${pack}"
  for f in server-ca.pem site.env agents/agent-i.pem agents/agent-i.key agents/agent-w.pem agents/agent-w.key; do
    [ -f "${HOME_DIR}/${f}" ] || die "the pack lacks ${f}: is it M1's m3.pack.tgz?"
  done
  chmod 600 "${HOME_DIR}"/agents/*.key
  printf '%s\n' "${app%/}" >"${STATE_DIR}/app-url"
  printf 'site M3\n' >"${HOME_DIR}/SITE"
  echo $((SECONDS - t0)) >"${STATE_DIR}/init-seconds"
  end_home
  echo "site M3: initialised in ${HOME_DIR}. Next: $0 m3 check"
}

m3_broker_url() { sed -n 's/^BROKER_URL=//p' "${HOME_DIR}/site.env"; }

# m3_decide AGENT CERT-AGENT JSON-BODY -> the cell's JSON answer on stdout (mTLS)
m3_decide() {
  curl -sS --cacert "${HOME_DIR}/server-ca.pem" --cert "${HOME_DIR}/agents/$2.pem" --key "${HOME_DIR}/agents/$2.key" \
    -X POST -d "$3" "$(m3_broker_url)/v1/actions"
}

m3_intent_body() { # m3_intent_body SUBJECT ACTION RESOURCE [BINDING [PROOF]]
  local intent
  intent=$(jq -cn --arg a "$2" --arg r "$3" --arg b "${4:-}" --arg p "${5:-}" \
    '{action:$a,resource:$r} + (if $b != "" then {plan_binding:$b} else {} end) + (if $p != "" then {quorum_proof:$p} else {} end)')
  jq -cn --arg s "$1" --arg i "${intent}" '{subject:$s,intent:$i}'
}

hex_to_b64() { perl -ne 'chomp; print pack("H*",$_)' | base64 -w0; }

# m3_present TOKEN-B64 ACTION RESOURCE -> prints "[HTTP code] body" from the application on M2
m3_present() {
  curl -sS -H "X-TBP-Token: $1" -w ' [%{http_code}]\n' "$(cat "${STATE_DIR}/app-url")/$2/$3"
}

m3_act() {
  require_init
  local agent="" action="" resource="" binding="" proof="" as="" nocert=0 positional=() resp tok
  while [ $# -gt 0 ]; do
    case "$1" in
      --binding) binding=${2:-}; shift 2 ;;
      --proof) proof=${2:-}; shift 2 ;;
      --as) as=${2:-}; shift 2 ;;
      --no-cert) nocert=1; shift ;;
      --*) die "act: unknown option $1" ;;
      *) positional+=("$1"); shift ;;
    esac
  done
  [ "${#positional[@]}" -eq 3 ] || die "usage: $0 m3 act <agent> <action> <resource> [--binding HEX] [--proof HEX] [--as <agent-cert>] [--no-cert]"
  agent=${positional[0]}; action=${positional[1]}; resource=${positional[2]}
  echo "1. ask the cell (M1) for a decision: ${agent} may ${action} ${resource}?"
  if [ "${nocert}" -eq 1 ]; then
    if resp=$(curl -sS --cacert "${HOME_DIR}/server-ca.pem" -X POST -d "$(m3_intent_body "${agent}" "${action}" "${resource}" "${binding}" "${proof}")" "$(m3_broker_url)/v1/actions" 2>&1); then
      echo "   answered without a client certificate: ${resp}"
    else
      echo "   refused at the TLS handshake, as it must be: $(printf '%s' "${resp}" | tail -1 | cut -c1-160)"
    fi
    return 0
  fi
  resp=$(m3_decide "${agent}" "${as:-${agent}}" "$(m3_intent_body "${agent}" "${action}" "${resource}" "${binding}" "${proof}")") || die "no answer from the cell"
  echo "   $(printf '%s' "${resp}" | jq -c '{allow,reason}')"
  tok=$(printf '%s' "${resp}" | jq -r '.token // empty')
  if [ -z "${tok}" ]; then echo "   no token: nothing to present."; return 0; fi
  printf '%s' "${tok}" | hex_to_b64 >"${STATE_DIR}/last-token"
  printf '%s %s\n' "${action}" "${resource}" >"${STATE_DIR}/last-call"
  echo "2. present the token to the application on M2:"
  echo "   $(m3_present "$(cat "${STATE_DIR}/last-token")" "${action}" "${resource}")"
}

# m3_call [ACTION RESOURCE] [--forge]: present the LAST token again (a replay), for another resource, or forged
m3_call() {
  require_init
  local forge=0 positional=() action resource tok
  while [ $# -gt 0 ]; do case "$1" in --forge) forge=1; shift ;; --*) die "call: unknown option $1" ;; *) positional+=("$1"); shift ;; esac; done
  [ -f "${STATE_DIR}/last-token" ] || die "no token yet: '$0 m3 act …' first"
  if [ "${#positional[@]}" -eq 2 ]; then action=${positional[0]}; resource=${positional[1]}; else read -r action resource <"${STATE_DIR}/last-call"; fi
  tok=$(cat "${STATE_DIR}/last-token")
  if [ "${forge}" -eq 1 ]; then tok=$(printf '%s' "${tok}" | base64 -d | perl -0777 -pe 'substr($_,length($_)-1,1)=chr(ord(substr($_,length($_)-1,1))^1)' | base64 -w0); fi
  echo "present the last token for: ${action} ${resource}$([ "${forge}" -eq 1 ] && echo ' (one byte flipped)')"
  echo "   $(m3_present "${tok}" "${action}" "${resource}")"
}

CHECK_FAILS=0
check() { # check DESCRIPTION EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then echo "  ok   - $1 ($3)"; else echo "  FAIL - $1: expected '$2', got '$3'"; CHECK_FAILS=$((CHECK_FAILS + 1)); fi
}

# m3_check: the plumbing, before any test — can this machine reach the cell and the server, and is each refused as it should be?
m3_check() {
  banner
  require_init
  CHECK_FAILS=0
  local body out
  body=$(m3_intent_body agent-i read doc-1)
  echo "1. the cell, over mutual TLS"
  out=$(m3_decide agent-i agent-i "${body}" 2>&1 | jq -r .reason 2>/dev/null || true)
  check "agent-i, its own certificate, no plan: reaches the broker and is refused" "plan-binding-required" "${out}"
  out=$(m3_decide agent-i agent-w "${body}" 2>&1 | jq -r .reason 2>/dev/null || true)
  check "agent-w's certificate claiming to be agent-i" "agent-transport-unbound" "${out}"
  out=$(curl -sS --cacert "${HOME_DIR}/server-ca.pem" -X POST -d "${body}" -o /dev/null -w '%{http_code}' "$(m3_broker_url)/v1/actions" 2>/dev/null || true)
  check "no client certificate: the handshake itself is refused (no HTTP answer at all)" "000" "${out}"
  echo "2. the application on M2"
  out=$(curl -sS -o /dev/null -w '%{http_code}' "$(cat "${STATE_DIR}/app-url")/healthz" 2>&1 || true)
  check "reachable" "200" "${out}"
  out=$(curl -sS -o /dev/null -w '%{http_code}' "$(cat "${STATE_DIR}/app-url")/read/doc-1" 2>&1 || true)
  check "no token: refused before pepd is even asked" "401" "${out}"
  echo
  if [ "${CHECK_FAILS}" -eq 0 ]; then echo "site M3: the plumbing works."; else die "check: ${CHECK_FAILS} unexpected result(s) — see above"; fi
}

m3_report() {
  require_init
  local n=30 i lat
  echo "### TBP dev-test report — M3 (the agent)"
  echo
  commit_line
  sysinfo_lines
  echo "- curl: $(curl --version | head -1 | awk '{print $2}')"
  echo "- init: $(cat "${STATE_DIR}/init-seconds" 2>/dev/null || echo "?") s"
  lat=$(mktemp "${STATE_DIR}/lat.XXXXXX")
  for i in $(seq 1 "${n}"); do
    curl -sS --cacert "${HOME_DIR}/server-ca.pem" --cert "${HOME_DIR}/agents/agent-i.pem" --key "${HOME_DIR}/agents/agent-i.key" \
      -X POST -d "$(m3_intent_body agent-i read doc-1)" -o /dev/null -w '%{time_total}\n' "$(m3_broker_url)/v1/actions" >>"${lat}" 2>/dev/null || true
  done
  echo "- decision round trip to the cell, mutual TLS, a new connection each time (the cheapest decision: no plan, refused), ${n} requests: p50 $(percentile 50 <"${lat}") ms, p95 $(percentile 95 <"${lat}") ms, max $(percentile 100 <"${lat}") ms"
  : >"${lat}"
  for i in $(seq 1 "${n}"); do
    curl -sS -o /dev/null -w '%{time_total}\n' "$(cat "${STATE_DIR}/app-url")/healthz" >>"${lat}" 2>/dev/null || true
  done
  echo "- application on M2, /healthz, ${n} requests: p50 $(percentile 50 <"${lat}") ms, p95 $(percentile 95 <"${lat}") ms, max $(percentile 100 <"${lat}") ms"
  rm -f -- "${lat}"
  echo "- what I tried and what happened: (write here)"
  echo "- where I got stuck: (write here)"
}

m3_reset() {
  local yes=0
  [ "${1:-}" != "-y" ] || yes=1
  if [ -e "${HOME_DIR}" ] && [ ! -f "${HOME_DIR}/SITE" ]; then die "${HOME_DIR} exists but is not a site home (no SITE marker): refusing to delete it"; fi
  if [ "${yes}" -eq 0 ]; then
    printf 'This DELETES %s (the agents'"'"' certificates). Type "reset" to go on: ' "${HOME_DIR}"
    read -r answer
    [ "${answer}" = "reset" ] || die "cancelled"
  fi
  rm -rf -- "${HOME_DIR}"
  echo "site M3: reset"
}

# --- dispatch ---------------------------------------------------------------------------------------

case "${ROLE}:${CMD}" in
  m1:init) m1_init "$@" ;;
  m1:up) m1_up ;;
  m1:down) m1_down ;;
  m1:status) m1_status ;;
  m1:grant) m1_grant "$@" ;;
  m1:mode-proof) m1_mode_proof "$@" ;;
  m1:pack) m1_make_packs; echo "site M1: packs rewritten in ${PACK_DIR}" ;;
  m1:report) m1_report ;;
  m1:reset) m1_reset "$@" ;;
  m2:init) m2_init "$@" ;;
  m2:up) m2_up ;;
  m2:down) m2_down ;;
  m2:status) m2_status ;;
  m2:mode) m2_mode "$@" ;;
  m2:report) m2_report ;;
  m2:reset) m2_reset "$@" ;;
  m3:init) m3_init "$@" ;;
  m3:check) m3_check ;;
  m3:act) m3_act "$@" ;;
  m3:call) m3_call "$@" ;;
  m3:report) m3_report ;;
  m3:reset) m3_reset "$@" ;;
  m1:listeners | m2:listeners | m3:listeners) cmd_listeners ;;
  *) usage ;;
esac
