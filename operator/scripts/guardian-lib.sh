#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Helpers for guardian.sh. Sourced, never run on its own.
#
# Everything a phase needs is derived: the stack config and outputs hold the
# bucket, the build pins and the slots, the enclave holds its own lifecycle, and
# the roster is the directory download-kp-pubkeys.sh verified. Nothing is cached
# between runs, so every phase is re-runnable and none can act on a stale fact.

# The all-zero PCR0 a mock-attestation build reports. Stacks whose eif-features
# include non-enclave-dev have no measurement to look up.
MOCK_PCR0=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
REQUIRED_CONFIG=(
  SUI_OPERATIONS GUARDIAN_ENV GUARDIAN_HOSTNAME BITCOIN_NETWORK
  S3_RETENTION_ENVIRONMENT SUI_RPC HASHI_PACKAGE_ID HASHI_OBJECT_ID
  KP_ROSTER_DIR KP_THRESHOLD
)
TUNNEL_PORTS=""
# Each pulumi call costs a round trip, and the waiting loops ask for these on
# every pass, so read them once.
CACHED_ACTIVE_SLOT=""
CACHED_BUCKET=""
CACHED_REGION=""

say() {
  printf '\n== %s ==\n' "$1"
}

note() {
  printf '   %s\n' "$1"
}

warn() {
  printf '\nWARNING: %s\n' "$1" >&2
}

die() {
  printf '\nERROR: %s\n' "$1" >&2
  exit 1
}

run_or_die() {
  local failure_message="$1"
  shift

  if ! "$@"; then
    die "$failure_message"
  fi
}

confirm() {
  local answer
  if ! IFS= read -r -p "$1 Type y/yes to continue: " answer; then
    die "No input received; nothing was done."
  fi
  case "$answer" in
    y | yes) ;;
    *) die "Not confirmed; nothing was done." ;;
  esac
}

# ── Operator configuration ────────────────────────────────────────────────

load_config() {
  local expected_env="$1" file="${GUARDIAN_CONFIG:-$REPO_ROOT/.hashi/guardian.env}" key
  [[ -f "$file" ]] \
    || die "No operator configuration at $file. Copy operator/guardian.env.sample there and fill it in."
  # shellcheck disable=SC1090  # the operator's own file, named above
  . "$file"
  for key in "${REQUIRED_CONFIG[@]}"; do
    [[ -n "${!key:-}" ]] || die "$file does not set $key."
  done
  # The environment is on every command line and checked here, so a command
  # typed from memory cannot land on another guardian.
  [[ "$expected_env" == "$GUARDIAN_ENV" ]] \
    || die "You asked for $expected_env, but $file configures $GUARDIAN_ENV."
  ENCLAVE_DIR="$SUI_OPERATIONS/pulumi/services/hashi-guardian-enclave"
  PROXY_DIR="$SUI_OPERATIONS/pulumi/services/hashi-guardian-proxy"
  [[ -d "$ENCLAVE_DIR" ]] || die "No guardian enclave stack at $ENCLAVE_DIR. Check SUI_OPERATIONS in $file."
  STACK="mysten/$GUARDIAN_ENV"
  RELAY="https://$GUARDIAN_HOSTNAME"
  RUN_DIR="$REPO_ROOT/.hashi/guardian-$GUARDIAN_ENV"
  mkdir -p "$RUN_DIR/logs"
  # Roster directories are usually written under .hashi, so accept them as
  # written there rather than as paths relative to wherever this was run from.
  [[ "$KP_ROSTER_DIR" == /* ]] || KP_ROSTER_DIR="$REPO_ROOT/$KP_ROSTER_DIR"
  if [[ -n "${NEW_KP_ROSTER_DIR:-}" && "$NEW_KP_ROSTER_DIR" != /* ]]; then
    NEW_KP_ROSTER_DIR="$REPO_ROOT/$NEW_KP_ROSTER_DIR"
  fi
}

# ── Pulumi ────────────────────────────────────────────────────────────────
# The only thing this driver needs sui-operations for. `-C` runs pulumi against
# that checkout's program without this script ever leaving the hashi repository.

pulumi_enclave() {
  pulumi -C "$ENCLAVE_DIR" --stack "$STACK" "$@"
}

pulumi_proxy() {
  pulumi -C "$PROXY_DIR" --stack "$STACK" "$@"
}

enclave_output() {
  pulumi_enclave stack output "$1" 2> /dev/null || true
}

enclave_cfg() {
  pulumi_enclave config get "hashi-guardian-enclave:$1" 2> /dev/null || true
}

enclave_cfg_set() {
  run_or_die "Could not set $1 on $STACK." \
    pulumi_enclave config set "hashi-guardian-enclave:$1" "$2" > /dev/null
}

# Slot config keys follow enclave.go: slot a reads the legacy unsuffixed keys,
# slot b the `-b` suffixed ones.
slot_key() {
  if [[ "$1" == a ]]; then printf '%s' "$2"; else printf '%s-%s' "$2" "$1"; fi
}

slot_urn() {
  printf 'urn:pulumi:%s::hashi-guardian-enclave::aws:ec2/instance:Instance::hashi-guardian-enclave-%s' \
    "$GUARDIAN_ENV" "$1"
}

slot_port() {
  if [[ "$1" == a ]]; then printf 13000; else printf 13100; fi
}

# Which letter serves and which is spare alternates with every guardian
# rotation, so no phase names a letter.
active_slot() {
  if [[ -z "$CACHED_ACTIVE_SLOT" ]]; then
    CACHED_ACTIVE_SLOT="$(enclave_output active_slot)"
    [[ -n "$CACHED_ACTIVE_SLOT" ]] || die "The enclave stack exports no active_slot."
  fi
  printf '%s' "$CACHED_ACTIVE_SLOT"
}

other_slot() {
  if [[ "$1" == a ]]; then printf b; else printf a; fi
}

standby_slot() {
  other_slot "$(active_slot)"
}

attestation_is_mock() {
  case ",$(enclave_cfg eif-features)," in
    *,non-enclave-dev,*) return 0 ;;
    *) return 1 ;;
  esac
}

# A mistyped URN targets nothing, and pulumi reports that as a clean no-op, so
# prove the resource exists before trusting a targeted update.
assert_urn_exists() {
  local export_file
  export_file="$(mktemp)"
  pulumi_enclave stack export > "$export_file"
  if ! grep -q "\"urn\": \"$1\"" "$export_file"; then
    rm -f "$export_file"
    die "No resource with URN $1 in $STACK."
  fi
  rm -f "$export_file"
}

# Refuse an enclave update whose plan is not exactly what the phase means.
# Untargeted, UserDataReplaceOnChange turns any drift in the other slot's
# rendered user-data into a replacement of the serving guardian, so a plan that
# does more than the phase intends must be read by a human, not executed.
#   assert_plan REQUIRED ALLOWED [preview args...]
#     REQUIRED  a change line must match this ("" = nothing required)
#     ALLOWED   every change line must match this
assert_plan() {
  local required="$1" allowed="$2" log summary
  shift 2
  log="$RUN_DIR/logs/preview-$(date -u +%Y%m%dT%H%M%SZ).log"
  if ! pulumi_enclave preview --non-interactive "$@" > "$log" 2>&1; then
    tail -20 "$log"
    die "The pulumi preview failed; see $log"
  fi
  summary="$(sed -n '/^Resources:/,/^$/p' "$log" | sed '1d;/^$/d;s/^ *//' | tr -s ' ')"
  PLAN_CHANGES="$(grep -E "to (create|update|replace|delete)" <<< "$summary" || true)"
  note "plan: $(tr '\n' ';' <<< "$summary")"
  if [[ -n "$PLAN_CHANGES" ]] && grep -qvE "$allowed" <<< "$PLAN_CHANGES"; then
    die "The plan contains changes this step must not make: $(grep -vE "$allowed" <<< "$PLAN_CHANGES" | tr '\n' ';')"
  fi
  if [[ -n "$required" ]] && ! grep -qE "$required" <<< "$PLAN_CHANGES"; then
    die "The plan lacks the change this step exists to make ($required)."
  fi
}

pulumi_up_slot() {
  local log
  log="$RUN_DIR/logs/enclave-up-$(date -u +%Y%m%dT%H%M%SZ).log"
  note "pulumi up, targeted at slot $1 -> $log"
  if ! pulumi_enclave up --yes --non-interactive \
    --target "$(slot_urn "$1")" --target-dependents > "$log" 2>&1; then
    tail -30 "$log"
    die "The pulumi up failed; see $log"
  fi
  grep -E "^\s+\+|^\s+-|^\s+~|Resources:" "$log" | tail -8
}

# A previous proxy up holds the stack lock through the whole ECS steady-state
# wait, well after the new task is serving. The phases that roll the proxy are
# exactly the ones that overlap it, so wait rather than fail.
pulumi_up_proxy() {
  local log attempt
  log="$RUN_DIR/logs/proxy-up-$(date -u +%Y%m%dT%H%M%SZ).log"
  note "proxy pulumi up -> $log (an ECS roll takes several minutes)"
  for attempt in $(seq 1 40); do
    if pulumi_proxy up --yes --non-interactive --refresh > "$log" 2>&1; then
      grep -E "Resources:|created|updated|replaced|deleted|unchanged" "$log" | tail -3
      return 0
    fi
    if grep -q "Another update is currently in progress" "$log" && ((attempt < 40)); then
      note "stack locked by another update; retrying in 30 seconds [$attempt]"
      sleep 30
      continue
    fi
    tail -30 "$log"
    die "The proxy pulumi up failed; see $log"
  done
  die "The proxy stack stayed locked."
}

# ── The hosts, over SSM ───────────────────────────────────────────────────

ssm_run() {
  local instance="$1" command="$2" command_id attempt status=Pending
  command_id="$(aws ssm send-command --instance-ids "$instance" --document-name AWS-RunShellScript \
    --parameters "{\"commands\":[\"$command\"]}" --query Command.CommandId --output text)"
  for attempt in $(seq 1 60); do
    status="$(aws ssm get-command-invocation --instance-id "$instance" --command-id "$command_id" \
      --query Status --output text 2> /dev/null || printf Pending)"
    case "$status" in
      Success | Failed | Cancelled | TimedOut) break ;;
    esac
    sleep 2
  done
  aws ssm get-command-invocation --instance-id "$instance" --command-id "$command_id" \
    --query StandardOutputContent --output text
  [[ "$status" == Success ]] || return 1
}

# A host compiles its EIF at first boot: minutes on a large instance, up to
# about an hour on a small one.
wait_host_bootstrap() {
  local instance="$1" attempt output
  note "waiting for $instance to finish its bootstrap (it builds the EIF)"
  for attempt in $(seq 1 120); do
    output="$(ssm_run "$instance" 'tail -3 /var/log/hashi-guardian-bootstrap.log 2>/dev/null' 2> /dev/null || true)"
    if grep -q "user-data complete" <<< "$output"; then
      note "bootstrap complete"
      return 0
    fi
    if grep -q "user-data FAILED" <<< "$output"; then
      printf '%s\n' "$output"
      die "The bootstrap of $instance failed. Read /var/log/hashi-guardian-bootstrap.log over SSM."
    fi
    if ((attempt % 6 == 0)); then
      note "still building: $(tail -1 <<< "$output" | cut -c 1-100)"
    fi
    sleep 30
  done
  die "Host $instance never finished bootstrapping."
}

# A cross-check only. The trusted value comes from the reproducible CI build;
# reading it off the host being verified would make the check circular.
host_pcr0() {
  ssm_run "$1" 'nitro-cli describe-enclaves | jq -r .[0].Measurements.PCR0'
}

# `aws ssm start-session` execs session-manager-plugin as a grandchild, so
# killing the aws process orphans a listener that still holds the local port and
# points at a host that may since have been replaced. Own tunnels by port.
kill_port() {
  local pids
  pids="$(lsof -ti "tcp:$1" -sTCP:LISTEN 2> /dev/null || true)"
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086  # whitespace-separated pids
    kill $pids 2> /dev/null || true
  fi
}

open_tunnel() {
  local instance="$1" port="$2" attempt
  kill_port "$port"
  aws ssm start-session --target "$instance" --document-name AWS-StartPortForwardingSession \
    --parameters "{\"portNumber\":[\"3000\"],\"localPortNumber\":[\"$port\"]}" \
    > "$RUN_DIR/logs/tunnel-$port.log" 2>&1 &
  TUNNEL_PORTS="$TUNNEL_PORTS $port"
  for attempt in $(seq 1 30); do
    if (exec 3<> "/dev/tcp/127.0.0.1/$port") 2> /dev/null; then
      return 0
    fi
    sleep 2
  done
  die "No SSM tunnel to $instance on port $port; see $RUN_DIR/logs/tunnel-$port.log"
}

close_tunnels() {
  local port
  for port in $TUNNEL_PORTS; do
    kill_port "$port"
  done
  TUNNEL_PORTS=""
# Each pulumi call costs a round trip, and the waiting loops ask for these on
# every pass, so read them once.
CACHED_ACTIVE_SLOT=""
CACHED_BUCKET=""
CACHED_REGION=""
}

# ── The guardian tools ────────────────────────────────────────────────────

# Build with the stack's own features: a mock-attestation stack needs a CLI that
# trusts its mock attestations, and a real one must never be built that way.
init_build() {
  local features=()
  if attestation_is_mock; then
    features=(--features non-enclave-dev)
  fi
  run_or_die "Could not build hashi-guardian-init." \
    cargo build --release --locked --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p hashi-guardian-init ${features[@]+"${features[@]}"}
  INIT_BIN="$(cargo metadata --format-version 1 --no-deps \
    --manifest-path "$REPO_ROOT/Cargo.toml" | jq -r .target_directory)/release/hashi-guardian-init"
  [[ -x "$INIT_BIN" ]] || die "No hashi-guardian-init binary at $INIT_BIN"
}

fetch_field() {
  "$INIT_BIN" tools fetch-info --endpoint "$1" --field "$2" 2> /dev/null
}

wait_guardian() {
  local endpoint="$1" attempt
  for attempt in $(seq 1 60); do
    if fetch_field "$endpoint" signing-pub-key > /dev/null 2>&1; then
      return 0
    fi
    if ((attempt % 6 == 0)); then
      note "the guardian at $endpoint is not answering yet [$attempt/60]"
    fi
    sleep 10
  done
  die "The guardian at $endpoint never answered."
}

# Key provisioner commands refuse a session with no heartbeat in S3, and an
# enclave writes its first one about a minute after operator init. Heartbeat
# keys are heartbeat/YYYY/MM/DD/HH/<session>-<seq>.json.
wait_heartbeat() {
  local session="$1" attempt hour key
  note "waiting for session $session to write its first heartbeat"
  for attempt in $(seq 1 30); do
    for hour in "$(date -u +%Y/%m/%d/%H)" "$(date -u -v-1H +%Y/%m/%d/%H)"; do
      key="$(aws s3api list-objects-v2 --bucket "$(guardian_bucket)" \
        --prefix "heartbeat/$hour/$session-" --max-items 1 \
        --query 'Contents[0].Key' --output text 2> /dev/null || true)"
      case "$key" in
        "" | None) ;;
        *)
          note "heartbeat $key"
          return 0
          ;;
      esac
    done
    sleep 10
  done
  die "No heartbeat for session $session after 5 minutes. Is the enclave running?"
}

# ── Derived facts ─────────────────────────────────────────────────────────

# The stack output, not the config key: the config holds the base name and the
# deployed bucket carries a per-key-lifetime suffix.
guardian_bucket() {
  if [[ -z "$CACHED_BUCKET" ]]; then
    CACHED_BUCKET="$(enclave_output s3_bucket_name)"
    [[ -n "$CACHED_BUCKET" ]] || die "$STACK exports no s3_bucket_name."
  fi
  printf '%s' "$CACHED_BUCKET"
}

guardian_region() {
  if [[ -z "$CACHED_REGION" ]]; then
    CACHED_REGION="$(enclave_output s3_bucket_region)"
    [[ -n "$CACHED_REGION" ]] || die "$STACK exports no s3_bucket_region."
  fi
  printf '%s' "$CACHED_REGION"
}

# Instances are exported by role, while config keys and URNs are by letter.
slot_instance() {
  if [[ "$1" == "$(active_slot)" ]]; then
    enclave_output enclave_instance_id
  else
    enclave_output standby_instance_id
  fi
}

slot_revision() {
  local revision
  revision="$(enclave_cfg "$(slot_key "$1" hashi-commit)")"
  [[ -n "$revision" ]] || die "$STACK has no $(slot_key "$1" hashi-commit)."
  printf '%s' "$revision"
}

slot_pcr0() {
  local pcr0
  if attestation_is_mock; then
    printf '%s' "$MOCK_PCR0"
    return 0
  fi
  pcr0="$(enclave_cfg "$(slot_key "$1" eif-pcr0)")"
  [[ -n "$pcr0" ]] \
    || die "$STACK has no $(slot_key "$1" eif-pcr0). Measure the build first: guardian.sh $GUARDIAN_ENV measure withdraw"
  printf '%s' "$pcr0"
}

ceremony_pcr0() {
  local pcr0
  if attestation_is_mock; then
    printf '%s' "$MOCK_PCR0"
    return 0
  fi
  pcr0="$(enclave_cfg ceremony-pcr0)"
  [[ -n "$pcr0" ]] \
    || die "$STACK has no ceremony-pcr0. Measure the build first: guardian.sh $GUARDIAN_ENV measure ceremony"
  printf '%s' "$pcr0"
}

# ── The roster ────────────────────────────────────────────────────────────
# One line per key provisioner, in the fingerprint order a ceremony deals, from
# the directory download-kp-pubkeys.sh verified. Deriving it from the
# certificates keeps a later re-download in the same order by construction.

roster_ids() {
  local dir="$1"
  [[ -f "$dir/roster.txt" ]] \
    || die "No verified roster at $dir/roster.txt. Run download-kp-pubkeys.sh and use its directory."
  awk '{print $2}' "$dir/roster.txt"
}

roster_paths() {
  local dir="$1" id
  while IFS= read -r id; do
    [[ -f "$dir/$id/$id-kp-pubkey.asc" ]] || die "No certificate for $id in $dir."
    printf '%s/%s/%s-kp-pubkey.asc\n' "$dir" "$id" "$id"
  done < <(roster_ids "$dir")
}

# ── Config rendering ──────────────────────────────────────────────────────
# One renderer for the operator's config and the key provisioners' packet, so
# the config_hash they each derive cannot drift.
#
#   render_config OUT PHASE ENDPOINT CERT_DIR CREDENTIALS
#     PHASE        ceremony | withdraw | rotate-signer | rotate-ceremony
#     ENDPOINT     guardian_endpoint: the operator's tunnel, or the public relay
#     CERT_DIR     directory the roster paths are written relative to, or empty
#                  for the absolute paths of the verified roster directory
#     CREDENTIALS  static  -> the stack's S3 key, which OperatorInit installs in
#                            the enclave for the life of the session
#                  environment -> omitted, so the caller supplies them

render_config() {
  local out="$1" phase="$2" endpoint="$3" cert_dir="$4" credentials="$5"
  local roster_dir="$KP_ROSTER_DIR" threshold="$KP_THRESHOLD" new_block=""
  if [[ "$phase" == rotate-ceremony ]]; then
    roster_dir="${NEW_KP_ROSTER_DIR:?rotate-ceremony needs NEW_KP_ROSTER_DIR}"
    threshold="${NEW_KP_THRESHOLD:?rotate-ceremony needs NEW_KP_THRESHOLD}"
  fi
  local paths count
  paths="$(render_roster_list "$roster_dir" "$cert_dir")"
  count="$(roster_ids "$roster_dir" | grep -c .)"
  if [[ "$phase" == rotate-signer ]]; then
    new_block="new_kp_roster:
  num_shares: $(roster_ids "${NEW_KP_ROSTER_DIR:?rotate-signer needs NEW_KP_ROSTER_DIR}" | grep -c .)
  threshold: ${NEW_KP_THRESHOLD:?rotate-signer needs NEW_KP_THRESHOLD}
  kp_pgp_cert_paths:
$(render_roster_list "$NEW_KP_ROSTER_DIR" "$cert_dir")"
  fi
  local credential_block="  access_key:
  secret_key:"
  if [[ "$credentials" == static ]]; then
    credential_block="  access_key: \"$(enclave_output s3_access_key_id)\"
  secret_key: \"$(pulumi_enclave stack output s3_secret_access_key --show-secrets)\""
  fi
  cat > "$out" << EOF
guardian_endpoint: "$endpoint"
relay_endpoint: "$RELAY"
bitcoin_network: "$BITCOIN_NETWORK"
guardian_s3:
  bucket: "$(guardian_bucket)"
  region: "$(guardian_region)"
$credential_block
  retention_environment: "$S3_RETENTION_ENVIRONMENT"
hashi:
  sui_rpc: "$SUI_RPC"
  package_id: "$HASHI_PACKAGE_ID"
  hashi_object_id: "$HASHI_OBJECT_ID"
kp_roster:
  num_shares: $count
  threshold: $threshold
  kp_pgp_cert_paths:
$paths
$(render_allowlist "$phase")
$new_block
limiter_config:
  refill_rate: $(enclave_cfg refill-rate-sats-per-sec)
  max_bucket_capacity: $(enclave_cfg max-bucket-capacity-sats)
EOF
  chmod 600 "$out"
}

render_roster_list() {
  local dir="$1" cert_dir="$2" path out=""
  while IFS= read -r path; do
    if [[ -n "$cert_dir" ]]; then
      path="$cert_dir/$(basename "$path")"
    fi
    out="${out}${out:+$'\n'}    - \"$path\""
  done < <(roster_paths "$dir")
  printf '%s' "$out"
}

# The ceremony enclave reports its revision with a `-ceremony` suffix, because
# PcrAllowlist forbids two entries for one revision and the ceremony build
# measures differently from the withdraw build at the same commit.
render_allowlist() {
  local deployed slot
  # The commit the serving guardian was deployed at: what the ceremony that
  # dealt these shares, and every log since, was written by.
  deployed="$(slot_revision "$(active_slot)")"
  # A mock build compiles the `-ceremony` suffix out (hashi-guardian
  # `reported_git_revision`) and skips attestation, so its ceremony and withdraw
  # enclaves share one allowlist entry.
  if attestation_is_mock; then
    printf '  current_build:\n    git_revision: "%s"\n    pcr0: "%s"\n  prev_builds: []\n' \
      "$deployed" "$MOCK_PCR0"
    return 0
  fi
  case "$1" in
    ceremony | rotate-ceremony)
      printf '  current_build:\n    git_revision: "%s-ceremony"\n    pcr0: "%s"\n  prev_builds: []\n' \
        "$deployed" "$(ceremony_pcr0)"
      ;;
    rotate-signer)
      # The rotation's ceremony enclave reads the dealt set's kp-shares, which a
      # withdraw build may have written, so that build stays trusted.
      printf '  current_build:\n    git_revision: "%s-ceremony"\n    pcr0: "%s"\n  prev_builds:\n    - git_revision: "%s"\n      pcr0: "%s"\n' \
        "$deployed" "$(ceremony_pcr0)" "$deployed" "$(slot_pcr0 "$(active_slot)")"
      ;;
    withdraw-*)
      slot="${1#withdraw-}"
      printf '  current_build:\n    git_revision: "%s"\n    pcr0: "%s"\n  prev_builds:\n' \
        "$(slot_revision "$slot")" "$(slot_pcr0 "$slot")"
      if [[ "$(slot_revision "$slot")" != "$deployed" ]]; then
        printf '    - git_revision: "%s"\n      pcr0: "%s"\n' \
          "$deployed" "$(slot_pcr0 "$(active_slot)")"
      fi
      printf '    - git_revision: "%s-ceremony"\n      pcr0: "%s"\n' \
        "$deployed" "$(ceremony_pcr0)"
      ;;
    *) die "Unknown rendering phase: $1" ;;
  esac
}

# ── CI measurements ───────────────────────────────────────────────────────
# The only sanctioned PCR0 source: hashi's own guardian-enclave.yml, on the
# exact commit, bucket, region and mode the hosts build with. It builds on two
# runner images and the values must agree.

dispatch_measurement() {
  run_or_die "Could not dispatch the measurement workflow." \
    gh workflow run guardian-enclave.yml --repo MystenLabs/hashi --ref main \
    -f "git_revision=$2" -f "bucket_name=$(guardian_bucket)" \
    -f "aws_region=$(guardian_region)" -f "ceremony_mode=$1" -f features=
}

measurement_pcr0() {
  local run_id="$1" file values
  local dir="$RUN_DIR/measurements/$run_id"
  rm -rf "$dir"
  mkdir -p "$dir"
  run_or_die "Could not download the artifacts of run $run_id." \
    gh run download "$run_id" --repo MystenLabs/hashi --dir "$dir" > /dev/null 2>&1
  values=""
  for file in "$dir"/*/nitro.pcrs; do
    [[ -f "$file" ]] || die "Run $run_id produced no nitro.pcrs artifacts."
    values="$values$(awk '$2 == "PCR0" {print $1}' "$file")"$'\n'
  done
  values="$(sort -u <<< "$values" | sed '/^$/d')"
  [[ "$(grep -c . <<< "$values")" == 1 ]] \
    || die "Run $run_id: the runners disagree, or produced no PCR0: $values"
  printf '%s' "$values"
}
