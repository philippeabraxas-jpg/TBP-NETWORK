#!/usr/bin/env bash
# scripts/devtest/devtest.sh — a DEV-TEST deployment of TBP scale 2, in one command.
#
#   scripts/devtest/devtest.sh init      # keys, rules, bundle, environment — once
#   scripts/devtest/devtest.sh up        # OPA + brokerd, in the background
#   scripts/devtest/devtest.sh status
#   scripts/devtest/devtest.sh demo      # first actions: what is refused, what is allowed, and why
#   scripts/devtest/devtest.sh down
#   scripts/devtest/devtest.sh reset     # stop, delete everything this script made
#
# ⚠ NOT FOR PRODUCTION. Every key it makes is thrown-away and lives on THIS machine, so it proves nothing
# about key custody, about separation between real people, or about a genesis ceremony. What it is for: run the
# real binaries, with the real enforcement, and attack them (deploy/devtest.md).
#
# What is simplified: the ceremony (keys, genesis, rules are generated for you; the issuer key is a seed file
# instead of an HSM — the one development switch used, which is why /etc/tbp/DEV_ENVIRONMENT is created).
# What is NOT simplified: the quorum is k = 2 of n = 3, the operator keys keep their roles, brokerd runs the
# same chain it runs at scale 2, OPA serves a signed bundle on a Unix socket authenticated by its UID.
#
# Needs: opa, openssl, jq, curl, and either `go` (the version pinned by go.mod) or built binaries in dist/
# (scripts/release/build.sh). Run it as a normal user on a clean Debian 12 virtual machine; `sudo` is used once,
# to write the development sentinel.
#
# Environment: TBP_DEVTEST_HOME (default $HOME/tbp-devtest), OPA_BIN (default opa), DEVTEST_BIN_DIR (default dist).

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${SCRIPT_DIR}/../.." && pwd)

HOME_DIR=${TBP_DEVTEST_HOME:-"${HOME}/tbp-devtest"}
OPA_BIN=${OPA_BIN:-opa}
SRC_BIN_DIR=${DEVTEST_BIN_DIR:-"${REPO_ROOT}/dist"}
SENTINEL=/etc/tbp/DEV_ENVIRONMENT # fixed path, hard-coded in the binaries (#113)
CELL_ID=cell-devtest

BIN_DIR="${HOME_DIR}/bin"
OPA_DIR="${HOME_DIR}/opa"
KEYS_DIR="${HOME_DIR}/keys"
GENESIS_DIR="${HOME_DIR}/genesis"
RUN_DIR="${HOME_DIR}/run"
LOG_DIR="${HOME_DIR}/log"
STATE_DIR="${HOME_DIR}/state"
OPA_SOCK="${RUN_DIR}/opa.sock"
BROKER_SOCK="${RUN_DIR}/broker.sock"
ADMIN_SOCK="${RUN_DIR}/broker-admin.sock"
ENV_FILE="${HOME_DIR}/brokerd.env"
LAUNCH_CONF="${OPA_DIR}/opa-launch.conf"

banner() {
  cat <<'EOF'
================================================================================
  TBP DEV-TEST DEPLOYMENT — NOT FOR PRODUCTION
  Throw-away keys on this machine. No real data, no real agents, no network
  exposure. Read deploy/devtest.md before you attack it.
================================================================================
EOF
}

die() { echo "devtest: $*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing prerequisite: $1 ($2)"; }

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
}

# --- processes ------------------------------------------------------------------------------------

# pid_of NAME: the pid in the pidfile when it still names a live process of that program, else nothing.
pid_of() {
  local f="${RUN_DIR}/$1.pid" pid
  [ -f "$f" ] || return 0
  pid=$(cat "$f" 2>/dev/null || true)
  [ -n "$pid" ] || return 0
  # the name check keeps a recycled pid from being mistaken for ours
  if [ "$(ps -p "$pid" -o comm= 2>/dev/null || true)" = "$1" ]; then echo "$pid"; fi
}

stop_one() {
  local name=$1 pid i
  pid=$(pid_of "$name")
  [ -n "$pid" ] || { rm -f "${RUN_DIR}/${name}.pid"; return 0; }
  kill "$pid" 2>/dev/null || true
  for i in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  rm -f "${RUN_DIR}/${name}.pid"
}

# wait_for NAME SECONDS DESCRIPTION COMMAND... : wait until COMMAND succeeds; stop at once if process NAME has died
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

opa_health() { curl -fsS --unix-socket "${OPA_SOCK}" http://localhost/health; }
broker_stats() { curl -fsS --unix-socket "${ADMIN_SOCK}" http://localhost/v1/supervision/stats; }

# --- init -----------------------------------------------------------------------------------------

keygen() { # keygen KEYFILE KEYRING -> prints the public key (64 hex)
  local out pub
  out=$("${BIN_DIR}/quorumproof" keygen -key "$1" -keyring "$2") || die "quorumproof keygen failed for $1"
  pub=$(printf '%s\n' "$out" | tr ' ' '\n' | sed -n 's/^public=//p' | head -1)
  [ "${#pub}" -eq 64 ] || die "quorumproof keygen printed no public key: ${out}"
  printf '%s' "$pub"
}

install_binaries() {
  mkdir -p "${BIN_DIR}"
  local b
  for b in brokerd quorumproof tbp-audit; do
    if [ -x "${SRC_BIN_DIR}/${b}" ]; then
      cp -- "${SRC_BIN_DIR}/${b}" "${BIN_DIR}/${b}"
    else
      need go "or build the release binaries first: bash scripts/release/build.sh dist"
      local pkg
      case "$b" in
        brokerd) pkg=./src/broker/cmd/brokerd ;;
        quorumproof) pkg=./src/pep/cmd/quorumproof ;;
        tbp-audit) pkg=./src/registry/cmd/tbp-audit ;;
      esac
      (cd "${REPO_ROOT}" && go build -o "${BIN_DIR}/${b}" "${pkg}")
    fi
  done
}

write_sentinel() {
  if [ -e "${SENTINEL}" ]; then return 0; fi
  local content="DEV-TEST deployment made by scripts/devtest/devtest.sh. Remove with: scripts/devtest/devtest.sh reset"
  if [ -w "$(dirname "${SENTINEL}")" ] 2>/dev/null; then
    printf '%s\n' "${content}" >"${SENTINEL}"
  elif command -v sudo >/dev/null 2>&1; then
    sudo install -d -m 0755 "$(dirname "${SENTINEL}")"
    printf '%s\n' "${content}" | sudo tee "${SENTINEL}" >/dev/null
  else
    die "cannot write ${SENTINEL} (no write access, no sudo). brokerd refuses a seed-file issuer key without it."
  fi
  : >"${STATE_DIR}/sentinel-created-by-devtest"
}

cmd_init() {
  banner
  [ ! -e "${HOME_DIR}" ] || [ -z "$(ls -A "${HOME_DIR}" 2>/dev/null)" ] ||
    die "${HOME_DIR} already exists: 'devtest.sh up' to use it, 'devtest.sh reset' to start over"
  # A machine that already holds a real deployment is not a place for throw-away keys.
  for marker in /var/lib/tbp /etc/tbp/brokerd.env /etc/tbp/pepd.env /etc/tbp/quorum-keyring.json; do
    [ ! -e "${marker}" ] || die "${marker} exists: this machine looks like it holds a real TBP deployment. Use a clean machine."
  done
  need "${OPA_BIN}" "the Open Policy Agent binary, see deploy/cellule.md step 3"
  need openssl "apt install openssl"
  need jq "apt install jq (policies/gen_capabilities.sh uses it)"
  need curl "apt install curl"
  [ "${#RUN_DIR}" -le 80 ] || die "TBP_DEVTEST_HOME is too long for Unix socket paths (${#RUN_DIR} chars, max 80): use a shorter one"
  if [ "$(id -u)" -eq 0 ] && [ "${DEVTEST_ALLOW_ROOT:-}" != "1" ]; then
    die "do not run as root: use a normal user (sudo is used once, for the sentinel). In a throw-away container, DEVTEST_ALLOW_ROOT=1 allows it."
  fi

  INIT_CREATED=0
  cleanup() { if [ "${INIT_CREATED}" -eq 1 ]; then echo "devtest: init failed — removing ${HOME_DIR}" >&2; rm -rf -- "${HOME_DIR}"; fi; }
  trap cleanup EXIT
  umask 077
  mkdir -p "${HOME_DIR}"
  INIT_CREATED=1
  mkdir -p "${OPA_DIR}" "${KEYS_DIR}" "${GENESIS_DIR}" "${RUN_DIR}" "${LOG_DIR}" "${STATE_DIR}" "${HOME_DIR}/registry" "${HOME_DIR}/audit"

  echo "== 1/6 binaries"
  install_binaries
  # OPA is always run through a link named `opa`: gen_capabilities.sh looks for that name, and the process-name
  # check of `down` and `status` relies on it.
  ln -sf -- "$(command -v "${OPA_BIN}")" "${BIN_DIR}/opa"

  echo "== 2/6 restricted OPA capabilities, signed rule bundle"
  (cd "${REPO_ROOT}" && PATH="${BIN_DIR}:${PATH}" sh policies/gen_capabilities.sh >"${LOG_DIR}/gen_capabilities.log") ||
    die "policies/gen_capabilities.sh failed — see ${LOG_DIR}/gen_capabilities.log"
  cp -- "${REPO_ROOT}/policies/capabilities.json" "${OPA_DIR}/capabilities.json"
  openssl genrsa -out "${OPA_DIR}/policy-signing.key" 2048 2>/dev/null
  openssl rsa -in "${OPA_DIR}/policy-signing.key" -pubout -out "${OPA_DIR}/policy-verify.pub" 2>/dev/null
  POLICY_ID=$(cd "${REPO_ROOT}" && sha256sum -- policies/rego/*.rego | sha256sum | cut -d' ' -f1)
  (cd "${REPO_ROOT}" && "${BIN_DIR}/opa" build --capabilities "${OPA_DIR}/capabilities.json" --revision "${POLICY_ID}" \
    --signing-key "${OPA_DIR}/policy-signing.key" --signing-alg RS256 \
    -b policies/rego/ -o "${OPA_DIR}/bundle.tar.gz")
  # the launch description brokerd measures (TBP_PROVISIONING_OPA_CONFIG) IS the argument list `up` runs
  {
    echo "run"; echo "--server"; echo "--addr"; echo "unix://${OPA_SOCK}"
    echo "--bundle"; echo "${OPA_DIR}/bundle.tar.gz"
    echo "--verification-key"; echo "${OPA_DIR}/policy-verify.pub"
    echo "--verification-key-id"; echo "default"
  } >"${LAUNCH_CONF}"

  echo "== 3/6 three controllers, k = 2 (quorumproof keygen)"
  local ctl_pubs=() i
  for i in 1 2 3; do
    ctl_pubs+=("$(keygen "${KEYS_DIR}/controller-${i}.key" "${KEYS_DIR}/quorum-keyring.json")")
  done
  printf '{"pubkeys":["%s","%s","%s"]}\n' "${ctl_pubs[0]}" "${ctl_pubs[1]}" "${ctl_pubs[2]}" >"${GENESIS_DIR}/manifest.json"

  echo "== 4/6 four operator keys, with roles"
  local op_pubs=()
  for i in 1 2 3 4; do
    op_pubs+=("$(keygen "${KEYS_DIR}/operator-${i}.key" "${KEYS_DIR}/operator-${i}-ring.json")")
  done
  # operator-1, operator-2: approve; operator-3: the night duty (cut, never widen); operator-4: submits plans.
  # submitter != approver, and at k = 2 a class-F or class-W plan needs two distinct approvers.
  jq -n --arg a "${op_pubs[0]}" --arg b "${op_pubs[1]}" --arg c "${op_pubs[2]}" --arg d "${op_pubs[3]}" \
    '[{key:$a,roles:["approve"]},{key:$b,roles:["approve"]},{key:$c,roles:["revoke","arbitrate"]},{key:$d,roles:["submit"]}]' \
    >"${HOME_DIR}/operators.json"
  # one agent per class: F = 0 (financial), I = 1 (infrastructure), W = 2 (survival)
  printf '{"agent-f":{"class":0},"agent-i":{"class":1},"agent-w":{"class":2}}\n' >"${HOME_DIR}/agents.json"

  echo "== 5/6 cell secrets and brokerd environment"
  openssl rand -hex 32 >"${HOME_DIR}/issuer.seed"
  "${BIN_DIR}/tbp-audit" keygen -out "${HOME_DIR}/brokerd-audit.key" >/dev/null
  {
    echo "# DEV-TEST environment — generated by scripts/devtest/devtest.sh. Not a production file."
    echo "TBP_CELL_ID=${CELL_ID}"
    echo "TBP_SALT=$(openssl rand -hex 16)"
    echo "TBP_POLICY_ID=${POLICY_ID}"
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
  } >"${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"

  echo "== 6/6 development sentinel (${SENTINEL})"
  write_sentinel
  printf 'devtest home: %s\ncell: %s\n' "${HOME_DIR}" "${CELL_ID}" >"${HOME_DIR}/DEVTEST"

  INIT_CREATED=0
  trap - EXIT
  echo
  echo "devtest: initialised in ${HOME_DIR}. Next: scripts/devtest/devtest.sh up"
  echo "         keys are in ${KEYS_DIR}: controller-1..3 (k = 2 of 3), operator-1..4 (see deploy/devtest.md)"
}

# --- up / down / status / reset --------------------------------------------------------------------

require_init() { [ -f "${HOME_DIR}/DEVTEST" ] || die "not initialised: run 'devtest.sh init' first (home: ${HOME_DIR})"; }

start_bg() { # start_bg NAME LOGFILE COMMAND...   (program name = NAME, used by pid_of)
  local name=$1 log=$2
  shift 2
  rm -f "${RUN_DIR}/${name}.pid"
  setsid nohup "$@" >"${log}" 2>&1 </dev/null &
  echo $! >"${RUN_DIR}/${name}.pid"
}

cmd_up() {
  banner
  require_init
  [ -e "${SENTINEL}" ] || die "${SENTINEL} is missing: brokerd would refuse its seed-file issuer key. Run 'devtest.sh init' again on a clean home."
  [ -z "$(pid_of opa)" ] && [ -z "$(pid_of brokerd)" ] || die "already running: 'devtest.sh status', or 'devtest.sh down' first"

  rm -f "${OPA_SOCK}" "${BROKER_SOCK}" "${ADMIN_SOCK}"
  local opa_args=()
  mapfile -t opa_args <"${LAUNCH_CONF}"
  start_bg opa "${LOG_DIR}/opa.log" "${BIN_DIR}/opa" "${opa_args[@]}"
  wait_for opa 20 "opa health (bundle signature verified)" opa_health

  start_bg brokerd "${LOG_DIR}/brokerd.log" bash -c 'set -a; . "$1"; set +a; exec "$2"' _ "${ENV_FILE}" "${BIN_DIR}/brokerd"
  wait_for brokerd 30 "brokerd stats" broker_stats
  if grep -q "AVERTISSEMENT quorum" "${LOG_DIR}/brokerd.log"; then
    die "brokerd warns about a fragile quorum — this deployment is not scale 2 (see ${LOG_DIR}/brokerd.log)"
  fi
  echo "devtest: up. OPA on ${OPA_SOCK}, brokerd on ${BROKER_SOCK}, admin on ${ADMIN_SOCK}"
  echo "         expected in ${LOG_DIR}/brokerd.log: a high-priority alarm that a development environment is declared."
  echo "         Next: deploy/devtest.md (first actions), scripts/devtest/devtest.sh status"
}

cmd_down() {
  [ -d "${RUN_DIR}" ] || { echo "devtest: nothing to stop"; return 0; }
  stop_one brokerd
  stop_one opa
  rm -f "${OPA_SOCK}" "${BROKER_SOCK}" "${ADMIN_SOCK}"
  echo "devtest: down"
}

cmd_status() {
  require_init
  local rc=0
  printf 'opa      : '; if [ -n "$(pid_of opa)" ] && opa_health >/dev/null 2>&1; then echo "up"; else echo "DOWN"; rc=1; fi
  printf 'brokerd  : '; if [ -n "$(pid_of brokerd)" ] && broker_stats >/dev/null 2>&1; then echo "up"; else echo "DOWN"; rc=1; fi
  if [ "$rc" -eq 0 ]; then echo "stats    : $(broker_stats)"; fi
  printf 'sentinel : '; if [ -e "${SENTINEL}" ]; then echo "present (${SENTINEL})"; else echo "ABSENT"; fi
  return "$rc"
}

cmd_reset() {
  local yes=0
  # `rm -rf` on a directory the user named: only ever on one that `init` made (it leaves this marker)
  if [ -e "${HOME_DIR}" ] && [ ! -f "${HOME_DIR}/DEVTEST" ]; then
    die "${HOME_DIR} exists but is not a devtest home (no DEVTEST marker): refusing to delete it"
  fi
  [ "${1:-}" != "-y" ] || yes=1
  if [ "$yes" -eq 0 ]; then
    printf 'This stops the deployment and DELETES %s (all keys and the registry). Type "reset" to go on: ' "${HOME_DIR}"
    read -r answer
    [ "${answer}" = "reset" ] || die "cancelled"
  fi
  cmd_down
  local made_sentinel=0
  [ -f "${STATE_DIR}/sentinel-created-by-devtest" ] && made_sentinel=1
  rm -rf -- "${HOME_DIR}"
  if [ "$made_sentinel" -eq 1 ] && [ -e "${SENTINEL}" ]; then
    if [ -w "$(dirname "${SENTINEL}")" ]; then rm -f "${SENTINEL}"; else sudo rm -f "${SENTINEL}" || echo "devtest: remove ${SENTINEL} by hand" >&2; fi
  fi
  echo "devtest: reset"
}

# --- demo -----------------------------------------------------------------------------------------

DEMO_FAILS=0
check() { # check DESCRIPTION EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then echo "  ok   - $1 ($3)"; else echo "  FAIL - $1: expected '$2', got '$3'"; DEMO_FAILS=$((DEMO_FAILS + 1)); fi
}

# act SUBJECT ACTION RESOURCE [BINDING [PROOF_HEX]] -> the broker's JSON answer on the data socket
act() {
  local intent
  intent=$(jq -cn --arg a "$2" --arg r "$3" --arg b "${4:-}" --arg p "${5:-}" \
    '{action:$a,resource:$r} + (if $b != "" then {plan_binding:$b} else {} end) + (if $p != "" then {quorum_proof:$p} else {} end)')
  jq -cn --arg s "$1" --arg i "${intent}" '{subject:$s,intent:$i}' |
    curl -sS --unix-socket "${BROKER_SOCK}" -X POST -d @- http://localhost/v1/actions
}

# admin_post PATH FILE -> prints "HTTP-STATUS BODY" from the admin socket
admin_post() {
  curl -sS --unix-socket "${ADMIN_SOCK}" -X POST -d @"$2" -w ' %{http_code}' "http://localhost$1"
}

# plan_for SUBJECT RESOURCE WORKDIR -> prints the plan hash after a signed submission by the submitting operator
plan_for() {
  printf '{"subject":"%s","steps":[{"action":"read","resource":"%s","params_hex":""}]}\n' "$1" "$2" >"$3/plan-$1.json"
  "${BIN_DIR}/quorumproof" plansubmit -cell "${CELL_ID}" -plan "$3/plan-$1.json" -key "${KEYS_DIR}/operator-4.key" -out "$3/sub-$1.json" 2>/dev/null
  curl -sS --unix-socket "${ADMIN_SOCK}" -X POST -d @"$3/sub-$1.json" http://localhost/v1/supervision/plan/submit | jq -r .plan_hash
}

cmd_demo() {
  banner
  require_init
  cmd_status >/dev/null || die "not running: 'devtest.sh up' first"
  local qp="${BIN_DIR}/quorumproof" w hash binding resp exp proof
  w=$(mktemp -d "${STATE_DIR}/demo.XXXXXX")
  # shellcheck disable=SC2064
  trap "rm -rf -- '${w}'" EXIT
  exp=$(date -u -d '+30 minutes' +%Y-%m-%dT%H:%M:%SZ)
  local policy_id
  policy_id=$(sed -n 's/^TBP_POLICY_ID=//p' "${ENV_FILE}")
  DEMO_FAILS=0

  echo "1. The cell refuses what it does not know, and what has no plan"
  check "unknown agent" "agent-unknown" "$(act agent-nobody read doc-1 | jq -r .reason)"
  check "class-I agent, no approved plan" "plan-binding-required" "$(act agent-i read doc-1 | jq -r .reason)"

  echo "2. Class I: one signed plan, one operator, one allowed action"
  hash=$(plan_for agent-i doc-1 "$w")
  check "plan submitted with a signature" "64" "${#hash}"
  "${qp}" planapprove -plan-hash "${hash}" -expires-at "${exp}" -key "${KEYS_DIR}/operator-1.key" -out "$w/appr-i.json" 2>/dev/null
  resp=$(admin_post /v1/supervision/plan/approve "$w/appr-i.json")
  check "approved by operator-1" '{"status":"approved"}' "$(printf '%s' "${resp}" | sed 's/ [0-9]*$//' | tr -d '\n')"
  binding=$("${qp}" planbind -plan-hash "${hash}")
  resp=$(act agent-i read doc-1 "${binding}")
  check "allowed, with a token" "true ok" "$(printf '%s' "${resp}" | jq -r '"\(.allow) \(.reason)"')"
  check "a signed token was issued" "true" "$(printf '%s' "${resp}" | jq -r '(.token | length) > 0')"

  echo "3. Class W: the plan needs two operators, the action needs two controllers"
  hash=$(plan_for agent-w doc-1 "$w")
  "${qp}" planapprove -plan-hash "${hash}" -expires-at "${exp}" -key "${KEYS_DIR}/operator-1.key" -out "$w/appr-w1.json" 2>/dev/null
  resp=$(admin_post /v1/supervision/plan/approve "$w/appr-w1.json")
  check "one operator is not enough for class W" "400" "${resp##* }"
  "${qp}" planapprove -plan-hash "${hash}" -expires-at "${exp}" -key "${KEYS_DIR}/operator-1.key" -key "${KEYS_DIR}/operator-2.key" -out "$w/appr-w2.json" 2>/dev/null
  resp=$(admin_post /v1/supervision/plan/approve "$w/appr-w2.json")
  check "approved by operator-1 and operator-2" "200" "${resp##* }"
  binding=$("${qp}" planbind -plan-hash "${hash}")
  check "no controller proof" "quorum-required" "$(act agent-w read doc-1 "${binding}" | jq -r .reason)"
  "${qp}" wproof -manifest "${GENESIS_DIR}/manifest.json" -action read -resource doc-1 -policy "${policy_id}" \
    -key "${KEYS_DIR}/controller-1.key" -out "$w/proof-1.json" 2>/dev/null
  proof=$(od -An -v -tx1 "$w/proof-1.json" | tr -d ' \n')
  check "one controller of two required" "quorum-insufficient" "$(act agent-w read doc-1 "${binding}" "${proof}" | jq -r .reason)"
  "${qp}" wproof -manifest "${GENESIS_DIR}/manifest.json" -action read -resource doc-1 -policy "${policy_id}" \
    -key "${KEYS_DIR}/controller-1.key" -key "${KEYS_DIR}/controller-3.key" -out "$w/proof-2.json" 2>/dev/null
  proof=$(od -An -v -tx1 "$w/proof-2.json" | tr -d ' \n')
  resp=$(act agent-w read doc-1 "${binding}" "${proof}")
  check "two controllers (the third is the spare)" "true ok" "$(printf '%s' "${resp}" | jq -r '"\(.allow) \(.reason)"')"
  check "the same proof does not work twice" "false" "$(act agent-w read doc-1 "${binding}" "${proof}" | jq -r .allow)"

  echo
  if [ "${DEMO_FAILS}" -eq 0 ]; then echo "devtest: demo passed. Every refusal above has a reason in the broker's registry (tbp-audit)."; else die "demo: ${DEMO_FAILS} unexpected result(s) — see above"; fi
}

case "${1:-}" in
  init) cmd_init ;;
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  demo) cmd_demo ;;
  reset) shift; cmd_reset "$@" ;;
  *) usage ;;
esac
