#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
PROTO_DIR="$REPO_ROOT/crates/hashi-types/proto"
ATTESTATION_SUFFIXES=(attestation-device.pem attestation-sig.pem attestation-dec.pem)
HOST_UNITS="hashi-guardian-enclave.service hashi-guardian-bridge.service hashi-vsock-proxy-8101.service hashi-vsock-proxy-8102.service hashi-vsock-proxy-8103.service"
STEPS="measure [slot] [run-id] | deploy | host [slot] | proxy | render [slot] | publish [slot] | tunnel [slot] | info [slot] | ceremony | new-session [slot] [--abandon] | provision [slot] [--do-genesis] | activate [slot]"

say() {
  printf '\n== %s ==\n' "$1"
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

cleanup() {
  if [[ -n "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
    cargo) printf '%s' "Rust toolchain (rustup)" ;;
    curl | mktemp) printf '%s' "standard system utilities" ;;
    gh) printf '%s' "GitHub CLI" ;;
    grpcurl) printf '%s' "grpcurl" ;;
    jq) printf '%s' "jq" ;;
    pulumi) printf '%s' "Pulumi CLI" ;;
  esac
}

# Reads from the guardian's Pulumi stack, so no step acts on a remembered value.
stack_output() {
  pulumi -C "$GUARDIAN_PULUMI_DIR" stack output "$@" --stack "$GUARDIAN_STACK"
}

# Reads the stack's configuration and outputs once, so a step sees one snapshot of both, and sets
# STACK_SLOTS to the slots it configures or still runs.
load_stack() {
  STACK_CONFIG="$(pulumi -C "$GUARDIAN_PULUMI_DIR" config --stack "$GUARDIAN_STACK" --json)" \
    || die "Could not read the configuration of stack $GUARDIAN_STACK in $GUARDIAN_PULUMI_DIR."
  STACK_OUTPUTS="$(stack_output --json)" \
    || die "Could not read the outputs of stack $GUARDIAN_STACK in $GUARDIAN_PULUMI_DIR."
  STACK_SLOTS="$(stack_slots)"
}

# Prints a configuration value, or nothing when the key is unset.
config_value() {
  jq -r --arg key "hashi-guardian-enclave:$1" '.[$key].value // empty' <<< "$STACK_CONFIG"
}

output_value() {
  jq -r --arg key "$1" '.[$key] // empty' <<< "$STACK_OUTPUTS"
}

# As the enclave program reads it: slot a is on unless disabled, slot b is off unless enabled.
slot_enabled() {
  local value
  value="$(config_value "slot-$1-enabled")"
  case "$value" in
    true) return 0 ;;
    false) return 1 ;;
    "") [[ "$1" == a ]] ;;
    *) die "Stack $GUARDIAN_STACK sets slot-$1-enabled to $value, not true or false." ;;
  esac
}

# Prints the role of a slot's deployed guardian: active, standby, or absent.
deployed_role() {
  local active
  active="$(output_value active_slot)"
  if [[ -z "$(output_value enclave_instance_id)" ]]; then
    printf 'absent'
  elif [[ "$1" == "${active:-a}" ]]; then
    printf 'active'
  elif [[ -n "$(output_value standby_instance_id)" ]]; then
    printf 'standby'
  else
    printf 'absent'
  fi
}

stack_slots() {
  local slot
  for slot in a b; do
    if slot_enabled "$slot" || [[ "$(deployed_role "$slot")" != absent ]]; then
      printf '%s\n' "$slot"
    fi
  done
}

# Sets SLOT to the slot named on the command line, or else to the stack's only slot.
select_slot() {
  if [[ -n "$SLOT_ARG" ]]; then
    SLOT="$SLOT_ARG"
  elif [[ "$STACK_SLOTS" == a || "$STACK_SLOTS" == b ]]; then
    SLOT="$STACK_SLOTS"
  elif [[ -z "$STACK_SLOTS" ]]; then
    die "Stack $GUARDIAN_STACK enables no guardian slot."
  else
    die "Stack $GUARDIAN_STACK has guardian slots a and b. Name the one this step acts on: $STEP a or $STEP b."
  fi
}

# Sets what a step needs about SLOT: its build, its deployed guardian, its tunnel and its rendered files.
load_slot() {
  local suffix="" port="$TUNNEL_PORT"
  if [[ "$SLOT" == b ]]; then
    suffix="-b"
    port=$((TUNNEL_PORT + 1))
  fi
  HASHI_COMMIT="$(config_value "hashi-commit$suffix")"
  [[ "$HASHI_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
    || die "Stack $GUARDIAN_STACK's hashi-commit$suffix is not a full commit: ${HASHI_COMMIT:-unset}"
  EIF_PCR0_KEY="eif-pcr0$suffix"
  SLOT_ROLE="$(deployed_role "$SLOT")"
  case "$SLOT_ROLE" in
    active) INSTANCE_ID="$(output_value enclave_instance_id)" ;;
    standby) INSTANCE_ID="$(output_value standby_instance_id)" ;;
    *) INSTANCE_ID="" ;;
  esac
  SLOT_PORT="$port"
  TUNNEL_ENDPOINT="http://127.0.0.1:$port"
  TUNNEL_DOWN="Could not reach slot $SLOT's guardian at $TUNNEL_ENDPOINT. Run the tunnel step for slot $SLOT again: it closes after 20 minutes without traffic."
  SLOT_DIR="$OUT_DIR/$SLOT"
  OPERATOR_CONFIG="$SLOT_DIR/operator.yaml"
}

# Sets GUARDIAN_BUCKET and REGION from what the stack has deployed.
read_bucket() {
  GUARDIAN_BUCKET="$(output_value s3_bucket_name)"
  REGION="$(output_value s3_bucket_region)"
  [[ -n "$GUARDIAN_BUCKET" && -n "$REGION" ]] \
    || die "Stack $GUARDIAN_STACK in $GUARDIAN_PULUMI_DIR has no deployed guardian. Run the deploy step first."
}

require_instance() {
  read_bucket
  [[ -n "$INSTANCE_ID" ]] || die "Slot $SLOT of stack $GUARDIAN_STACK has no deployed guardian."
}

# Runs a JSON array of shell commands on the guardian's host and prints their output.
run_on_host() {
  local command_id status=0
  if ! command_id="$(aws ssm send-command --region "$REGION" --instance-ids "$INSTANCE_ID" \
    --document-name AWS-RunShellScript --query Command.CommandId --output text --parameters "commands=$1")"; then
    return 1
  fi
  aws ssm wait command-executed --region "$REGION" --command-id "$command_id" --instance-id "$INSTANCE_ID" \
    || status=$?
  aws ssm get-command-invocation --region "$REGION" --command-id "$command_id" --instance-id "$INSTANCE_ID" \
    --query '[StandardOutputContent, StandardErrorContent]' --output text
  return "$status"
}

# Prints how many completed key ceremonies the log bucket holds.
count_ceremonies() {
  # The CLI paginates this listing and drops its KeyCount, so count the keys it returns.
  # shellcheck disable=SC2016
  aws s3api list-objects-v2 --region "$REGION" --bucket "$GUARDIAN_BUCKET" \
    --prefix ceremony/ --query 'length(Contents || `[]`)' --output text
}

guardian_init() {
  cargo run --release --locked --quiet --manifest-path "$REPO_ROOT/Cargo.toml" -p hashi-guardian-init -- "$@"
}

# The guardian's own report, unsigned, from its enclave through the slot's tunnel.
slot_info() {
  grpcurl -plaintext -max-time 15 -import-path "$PROTO_DIR" -proto sui/hashi/v1alpha/guardian_service.proto \
    -d '{}' "127.0.0.1:$SLOT_PORT" sui.hashi.v1alpha.GuardianService/GetGuardianInfo
}

# The report of the guardian the proxy's relay sends key provisioners to.
relay_info() {
  grpcurl -max-time 20 -import-path "$PROTO_DIR" -proto sui/hashi/v1alpha/guardian_relay_service.proto \
    -d '{}' "$PROXY_AUTHORITY" sui.hashi.v1alpha.GuardianRelayService/GetProvisioningTargetInfo
}

# grpcurl prints bytes as base64, where /info and the CLIs print hex.
hex_of() {
  [[ -n "$1" ]] || return 0
  base64 -d <<< "$1" | od -An -v -tx1 | tr -d ' \n'
}

# Prints a guardian's mode and stage, such as withdraw/ACTIVATED, or none before operator initialization.
lifecycle_of() {
  jq -r '(.info // .signedInfo.data)
    | if .withdraw then "withdraw/" + (.withdraw | ltrimstr("WITHDRAW_STAGE_"))
      elif .ceremony then "ceremony/" + (.ceremony | ltrimstr("CEREMONY_STAGE_"))
      else "none" end' <<< "$1"
}

# The operator's tools must be the guardian's build; scripts and documents may differ.
require_guardian_build() {
  git -C "$REPO_ROOT" cat-file -e "$HASHI_COMMIT^{commit}" 2> /dev/null \
    || die "This checkout does not have $HASHI_COMMIT, the commit slot $SLOT's guardian runs. Fetch it first."
  git -C "$REPO_ROOT" diff --quiet "$HASHI_COMMIT" -- Cargo.lock Cargo.toml crates \
    || die "This checkout's crates differ from $HASHI_COMMIT, the commit slot $SLOT's guardian runs. Check that commit out."
}

# gh reports the run a dispatch starts from 2.87 on, so check before dispatching one.
require_run_urls() {
  local version version_pattern='^gh version ([0-9]+)\.([0-9]+)'
  version="$(gh --version)" || die "Could not read the GitHub CLI's version."
  if [[ ! "$version" =~ $version_pattern ]] \
    || ((BASH_REMATCH[1] < 2 || (BASH_REMATCH[1] == 2 && BASH_REMATCH[2] < 87))); then
    die "This step needs GitHub CLI 2.87 or later, which reports the run it dispatches. Found: ${version%%$'\n'*}"
  fi
}

# Everything the operator and the key provisioners must agree on, with the endpoint each one reaches the guardian by.
write_config() {
  local guardian_endpoint="$1" cert
  printf 'guardian_endpoint: "%s"\nrelay_endpoint: "%s"\n\n' "$guardian_endpoint" "$GUARDIAN_PROXY_URL"
  printf 'deployment:\n  bucket_info:\n    name: "%s"\n    region: "%s"\n' "$GUARDIAN_BUCKET" "$REGION"
  printf '  retention_environment: "%s"\n  bitcoin_network: "%s"\n' "$RETENTION_ENVIRONMENT" "$BITCOIN_NETWORK"
  printf '  pcr_allowlist:\n    current_build:\n      git_revision: "%s"\n      pcr0: "%s"\n    prev_builds: []\n\n' \
    "$HASHI_COMMIT" "$EIF_PCR0"
  printf 'hashi:\n  sui_rpc: "%s"\n  package_id: "%s"\n  hashi_object_id: "%s"\n\n' \
    "$SUI_RPC" "$HASHI_PACKAGE_ID" "$HASHI_OBJECT_ID"
  printf 'kp_roster:\n  num_shares: %d\n  threshold: %d\n  kp_pgp_cert_paths:\n' "${#CERTS[@]}" "$KP_THRESHOLD"
  for cert in "${CERTS[@]}"; do
    printf '    - certs/%s\n' "$cert"
  done
  printf '\nlimiter_config:\n  refill_rate: %s\n  max_bucket_capacity: %s\n' "$REFILL_RATE" "$MAX_BUCKET_CAPACITY"
}

# Writes the slot's configuration into a directory: guardian-init.yaml for the key provisioners,
# operator.yaml for the operator, and the certificates both list.
render_into() {
  local dir="$1" cert other other_suffix=""
  read_bucket
  EIF_PCR0="$(config_value "$EIF_PCR0_KEY")"
  REFILL_RATE="$(config_value refill-rate-sats-per-sec)"
  MAX_BUCKET_CAPACITY="$(config_value max-bucket-capacity-sats)"
  [[ "$EIF_PCR0" =~ ^[0-9a-f]{96}$ ]] || die "$EIF_PCR0_KEY is not a PCR0 measurement: ${EIF_PCR0:-unset}"
  [[ -n "$REFILL_RATE" ]] || die "Stack $GUARDIAN_STACK has no refill-rate-sats-per-sec."
  [[ -n "$MAX_BUCKET_CAPACITY" ]] || die "Stack $GUARDIAN_STACK has no max-bucket-capacity-sats."
  # Every reader must allowlist each build that wrote the log, and this configuration lists one.
  other=a
  if [[ "$SLOT" == a ]]; then
    other=b
    other_suffix="-b"
  fi
  if [[ "$STACK_SLOTS" == *"$other"* ]] \
    && [[ "$(config_value "hashi-commit$other_suffix") $(config_value "eif-pcr0$other_suffix")" != "$HASHI_COMMIT $EIF_PCR0" ]]; then
    die "Slots a and b of stack $GUARDIAN_STACK have different builds. Both write one log bucket, so give slot $SLOT the same hashi-commit and eif-pcr0 as slot $other."
  fi

  [[ -f "$KP_ROSTER_DIR/roster.txt" ]] \
    || die "No verified roster in $KP_ROSTER_DIR. Run download-kp-pubkeys.sh first."
  rm -rf -- "$dir/certs"
  mkdir -p "$dir/certs"
  CERTS=()
  for cert in "$KP_ROSTER_DIR"/*/*-kp-pubkey.asc; do
    [[ -f "$cert" ]] || die "No certificates in $KP_ROSTER_DIR."
    cp -- "$cert" "${ATTESTATION_SUFFIXES[@]/#/${cert%.asc}.}" "$dir/certs/"
    CERTS+=("${cert##*/}")
  done

  write_config "$GUARDIAN_PROXY_URL" > "$dir/guardian-init.yaml"
  S3_ACCESS_KEY_ID="$(stack_output s3_access_key_id)" || die "Could not read the guardian's S3 access key."
  S3_SECRET_ACCESS_KEY="$(stack_output s3_secret_access_key --show-secrets)" \
    || die "Could not read the guardian's S3 secret key."
  # The enclave keeps the key it is initialized with, so this must be the stack's long-lived one.
  (
    umask 077
    rm -f -- "$dir/operator.yaml"
    {
      write_config "$TUNNEL_ENDPOINT"
      printf '\ns3_credentials:\n  access_key: "%s"\n  secret_key: "%s"\n' "$S3_ACCESS_KEY_ID" "$S3_SECRET_ACCESS_KEY"
    } > "$dir/operator.yaml"
  ) || die "Could not write $dir/operator.yaml."
}

# Stops unless the rendered configuration is what the render step would write now: the stack, the
# environment file and the roster can each have changed since it ran.
require_fresh_render() {
  local rendered stale=""
  [[ -f "$OPERATOR_CONFIG" ]] || die "No $OPERATOR_CONFIG. Run the render step for slot $SLOT first."
  WORK_DIR="$(mktemp -d)"
  render_into "$WORK_DIR"
  # Only the files a render writes: Finder, for one, adds its own to a directory it has shown.
  while IFS= read -r rendered; do
    cmp -s "$WORK_DIR/$rendered" "$SLOT_DIR/$rendered" || stale+="${stale:+, }$rendered"
  done < <(cd "$WORK_DIR" && find guardian-init.yaml operator.yaml certs -type f | sort)
  cleanup
  WORK_DIR=""
  [[ -z "$stale" ]] \
    || die "Out of date in $SLOT_DIR: $stale. The stack, $ENV_FILE or the roster changed after the render step. Run it again, then publish again and have every key provisioner download again, unless only operator.yaml is out of date."
}

# Stops unless the proxy leads key provisioners and nodes to the slot's guardian as its role says,
# and sets SLOT_INFO and SIGNING_KEY. The proxy fronts the active slot, and its relay sends key
# provisioners to a standby.
require_reached() {
  local proxy_key
  [[ -n "$INSTANCE_ID" ]] || die "Slot $SLOT of stack $GUARDIAN_STACK has no deployed guardian."
  SLOT_INFO="$(slot_info)" || die "$TUNNEL_DOWN"
  if ! SIGNING_KEY="$(hex_of "$(jq -r '.info.signingPubKey // empty' <<< "$SLOT_INFO")")" \
    || [[ ! "$SIGNING_KEY" =~ ^[0-9a-f]{64}$ ]]; then
    die "Slot $SLOT's guardian reported no signing key at $TUNNEL_ENDPOINT."
  fi
  if [[ "$SLOT_ROLE" == active ]]; then
    if ! PROXY_INFO="$(curl -fsS --max-time 15 "$GUARDIAN_PROXY_URL/info")" \
      || ! proxy_key="$(jq -r '.signingPubKey // empty' <<< "$PROXY_INFO")"; then
      die "The proxy does not answer at $GUARDIAN_PROXY_URL/info."
    fi
    [[ "$proxy_key" == "$SIGNING_KEY" ]] \
      || die "The proxy fronts guardian ${proxy_key:-none}, but $TUNNEL_ENDPOINT reaches slot $SLOT's $SIGNING_KEY. The proxy caches its view for 30 seconds: run this step again. If they still differ, check that the tunnel is slot $SLOT's, then roll the proxy."
  else
    if ! RELAY_INFO="$(relay_info)" \
      || ! proxy_key="$(hex_of "$(jq -r '.signedInfo.data.signingPubKey // empty' <<< "$RELAY_INFO")")"; then
      die "The proxy's relay does not answer at $PROXY_AUTHORITY."
    fi
    [[ "$proxy_key" == "$SIGNING_KEY" ]] \
      || die "The proxy's relay sends key provisioners to guardian ${proxy_key:-none}, but $TUNNEL_ENDPOINT reaches slot $SLOT's $SIGNING_KEY. Check that the tunnel is slot $SLOT's, then roll the proxy."
  fi
}

USAGE="Usage: $0 <env-file> <step>, where <step> is: $STEPS"
case "${1:-}" in
  -h | --help)
    printf '%s\n' "$USAGE" \
      "Runs one operator step against the guardian stack <env-file> names. With two guardian slots, name the slot." \
      "See operator/deploy.md."
    exit 0
    ;;
esac
(($# >= 2)) || die "$USAGE"
ENV_FILE="$1"
STEP="$2"
shift 2
SLOT_ARG=""
case "${1:-}" in
  a | b)
    SLOT_ARG="$1"
    shift
    ;;
esac
[[ -f "$ENV_FILE" ]] || die "No environment file at $ENV_FILE. Copy operator/guardian.env.sample."
# shellcheck source=/dev/null
. "$ENV_FILE"
for variable in GUARDIAN_PULUMI_DIR GUARDIAN_STACK GUARDIAN_PROXY_URL KP_NAME KP_ROSTER_DIR KP_THRESHOLD \
  SUI_RPC HASHI_PACKAGE_ID HASHI_OBJECT_ID BITCOIN_NETWORK RETENTION_ENVIRONMENT; do
  [[ -n "${!variable:-}" ]] || die "$ENV_FILE does not set $variable."
done
TUNNEL_PORT="${TUNNEL_PORT:-3000}"
[[ "$TUNNEL_PORT" =~ ^[0-9]+$ ]] || die "TUNNEL_PORT is not a port: $TUNNEL_PORT"
[[ "$GUARDIAN_PROXY_URL" =~ ^https://([A-Za-z0-9.-]+)$ ]] \
  || die "GUARDIAN_PROXY_URL must be https:// and a host name, with no path: $GUARDIAN_PROXY_URL"
PROXY_AUTHORITY="${BASH_REMATCH[1]}:443"

required_commands=(aws cargo curl gh grpcurl jq mktemp pulumi)
missing_commands=()
for required_command in "${required_commands[@]}"; do
  if ! command -v "$required_command" > /dev/null 2>&1; then
    missing_commands+=("$required_command")
  fi
done

if ((${#missing_commands[@]} > 0)); then
  printf 'The following required CLI tools are not installed or not on PATH:\n' >&2
  for missing_command in "${missing_commands[@]}"; do
    printf '  - %s (%s)\n' "$missing_command" "$(command_package "$missing_command")" >&2
  done
  printf '\nInstall the listed tools, then run this script again.\n' >&2
  exit 1
fi

# Set after the environment file is read, so nothing in it can name what the exit removes.
WORK_DIR=""
trap cleanup EXIT
OUT_DIR="$REPO_ROOT/.hashi/guardian/${GUARDIAN_STACK##*/}"
load_stack
case "$STEP" in
  deploy | proxy)
    [[ -z "$SLOT_ARG" ]] || die "The $STEP step acts on the whole stack, not one slot."
    ;;
  *)
    select_slot
    load_slot
    ;;
esac

case "$STEP" in
  measure)
    say "Measure slot $SLOT's guardian build at $HASHI_COMMIT"
    run_id="${1:-}"
    if [[ -z "$run_id" ]]; then
      require_run_urls
      if ! run_url="$(gh workflow run guardian-enclave.yml --repo MystenLabs/hashi --ref main \
        -f git_revision="$HASHI_COMMIT")"; then
        die "Could not dispatch the measurement."
      fi
      run_id="${run_url##*/}"
    fi
    [[ "$run_id" =~ ^[0-9]+$ ]] || die "Could not tell which run measures the build: $run_id"
    printf 'Measurement run: https://github.com/MystenLabs/hashi/actions/runs/%s\n' "$run_id"
    run_or_die "The measurement run did not succeed." \
      gh run watch "$run_id" --repo MystenLabs/hashi --exit-status > /dev/null
    # The run builds whatever commit and features it was given, so check it built this commit on
    # both runners, with no feature that changes the image, such as non-enclave-dev.
    if ! run_log="$(gh run view "$run_id" --repo MystenLabs/hashi --log)"; then
      die "Could not read the log of run $run_id."
    fi
    [[ "$(grep -c -- "checkout --progress --force $HASHI_COMMIT" <<< "$run_log")" == 2 ]] \
      || die "Run $run_id did not build $HASHI_COMMIT on both runners."
    if grep -qE 'FEATURES:[[:space:]]+[^[:space:]]' <<< "$run_log"; then
      die "Run $run_id built with extra features, so it does not measure the guardian's image."
    fi
    pcrs_dir="$(mktemp -d)"
    run_or_die "Could not download the measurements of run $run_id." \
      gh run download "$run_id" --repo MystenLabs/hashi --pattern 'nitro-pcrs-*' --dir "$pcrs_dir"
    measured="$(awk '/PCR0/ { print $1 }' "$pcrs_dir"/nitro-pcrs-*/nitro.pcrs | sort | uniq -c | awk '{ print $1 ":" $2 }')"
    rm -rf -- "$pcrs_dir"
    [[ "$measured" =~ ^2:([0-9a-f]{96})$ ]] || die "The two runners did not agree on one PCR0: $measured"
    measured="${BASH_REMATCH[1]}"
    printf 'PCR0: %s\n' "$measured"
    # The watch takes minutes, during which the operator may set the key it compares.
    load_stack
    configured="$(config_value "$EIF_PCR0_KEY")"
    [[ "$configured" == "$measured" ]] \
      || die "Stack $GUARDIAN_STACK has $EIF_PCR0_KEY ${configured:-unset}. Set it to the PCR0 above in its Pulumi.<stack>.yaml."
    printf 'It is the %s stack %s configures.\n' "$EIF_PCR0_KEY" "$GUARDIAN_STACK"
    ;;
  deploy)
    say "Deploy the guardian enclave stack $GUARDIAN_STACK"
    # An untargeted up re-renders every slot it plans, so with two it can replace the serving guardian.
    [[ "$STACK_SLOTS" != *$'\n'* ]] \
      || die "Stack $GUARDIAN_STACK has two guardian slots. The deploy step runs an untargeted pulumi up, which can replace either guardian."
    if ! plan="$(pulumi -C "$GUARDIAN_PULUMI_DIR" preview --stack "$GUARDIAN_STACK" --json)"; then
      # With --json, Pulumi reports what failed inside the plan it prints.
      jq -r '.diagnostics[]?.message // empty' <<< "$plan" >&2 || printf '%s\n' "$plan" >&2
      die "Could not preview stack $GUARDIAN_STACK."
    fi
    jq -r '.steps[] | select(.op != "same") | "  \(.op)  \(.urn | split("::") | .[-2:] | join("  "))"' <<< "$plan"
    jq -r '.changeSummary | to_entries | map("\(.value) \(.key)") | join(", ")' <<< "$plan"
    if [[ "$(jq -r '[.steps[] | select(.op != "same")] | length' <<< "$plan")" == 0 ]]; then
      printf 'Nothing to change.\n'
      exit 0
    fi
    # The plan leaves out an instance it deletes because the log bucket it depends on is replaced,
    # so any change is taken to risk every instance the stack has. An enclave holds the only live
    # copy of its key, and naming each instance is the consent to lose it.
    if ! existing="$(pulumi -C "$GUARDIAN_PULUMI_DIR" stack export --stack "$GUARDIAN_STACK" \
      | jq -r '.deployment.resources[]? | select(.type == "aws:ec2/instance:Instance") | .id')"; then
      die "Could not read the instances of stack $GUARDIAN_STACK."
    fi
    if [[ -n "$existing" ]]; then
      warn "This plan can destroy the guardian instances below. A destroyed guardian's key is gone from memory for good: it needs every step from provisioning again, or from the ceremony if the log bucket changes too."
      for instance_id in $existing; do
        if ! IFS= read -r -p "Type $instance_id to destroy that guardian: " typed_id; then
          die "No input received; nothing was changed."
        fi
        [[ "$typed_id" == "$instance_id" ]] || die "Not confirmed; nothing was changed."
      done
    else
      if ! IFS= read -r -p "Apply this plan to $GUARDIAN_STACK? Type y/yes to continue: " deploy_confirmation; then
        die "No input received; nothing was changed."
      fi
      case "$deploy_confirmation" in
        y | yes) ;;
        *) die "Not confirmed; nothing was changed." ;;
      esac
    fi
    up_status=0
    pulumi -C "$GUARDIAN_PULUMI_DIR" up --stack "$GUARDIAN_STACK" --yes || up_status=$?
    outcome="Deployed, but"
    ((up_status == 0)) || outcome="The deploy did not finish, and"
    # Rotation state describes earlier instances, so it is stale once none of them is left. A deploy
    # that fails partway can already have destroyed them, so this runs either way.
    if ! remaining="$(pulumi -C "$GUARDIAN_PULUMI_DIR" stack export --stack "$GUARDIAN_STACK" \
      | jq -r '.deployment.resources[]? | select(.type == "aws:ec2/instance:Instance") | .id')"; then
      die "$outcome could not read the instances of stack $GUARDIAN_STACK."
    fi
    survivors=0
    for instance_id in $existing; do
      if grep -qxF -- "$instance_id" <<< "$remaining"; then
        survivors=$((survivors + 1))
      fi
    done
    if ((survivors == 0)); then
      if ! rotation_tags="$(pulumi -C "$GUARDIAN_PULUMI_DIR" stack tag ls --stack "$GUARDIAN_STACK" --json \
        | jq -r 'keys[] | select(startswith("rotation:"))')"; then
        die "$outcome could not list the stack's rotation tags. Clear them before the next rotation."
      fi
      for rotation_tag in $rotation_tags; do
        run_or_die "$outcome could not clear $rotation_tag. Clear it before the next rotation." \
          pulumi -C "$GUARDIAN_PULUMI_DIR" stack tag rm "$rotation_tag" --stack "$GUARDIAN_STACK"
      done
    fi
    ((up_status == 0)) || die "The deploy did not finish. Preview the stack before running this step again."
    printf '\nDeployed. The host builds the enclave image at boot; follow it with the host step.\n'
    ;;
  host)
    require_instance
    say "Guardian host $INSTANCE_ID, slot $SLOT"
    # The boot log traces its own commands, so match only the lines the boot itself prints.
    host_report="$(run_on_host "[\"tail -n 12 /var/log/hashi-guardian-bootstrap.log\",\"grep -E '^\\\\[[^]]*\\\\] hashi-guardian user-data (complete|FAILED)' /var/log/hashi-guardian-bootstrap.log || echo 'The boot has not finished.'\",\"nitro-cli describe-enclaves\",\"systemctl is-active $HOST_UNITS || true\"]")" \
      || die "Could not read the host. A new instance takes a minute to accept commands."
    printf '%s\n' "$host_report"
    # Only a cross-check: key provisioners' tools verify PCR0 from a fresh attestation.
    pcr0_pattern='"PCR0": "([0-9a-f]{96})"'
    if [[ "$host_report" =~ $pcr0_pattern ]]; then
      if [[ "${BASH_REMATCH[1]}" == "$(config_value "$EIF_PCR0_KEY")" ]]; then
        printf '\nThe enclave reports the PCR0 that %s configures.\n' "$EIF_PCR0_KEY"
      else
        warn "The enclave reports PCR0 ${BASH_REMATCH[1]}, not the $EIF_PCR0_KEY stack $GUARDIAN_STACK configures. Key provisioners' tools will refuse it."
      fi
    fi
    ;;
  proxy)
    # The proxy serves nodes for the active slot, so it runs that slot's build.
    SLOT="$(output_value active_slot)"
    SLOT="${SLOT:-$(config_value active-slot)}"
    SLOT="${SLOT:-a}"
    load_slot
    say "Roll the guardian proxy to $HASHI_COMMIT"
    require_run_urls
    # The workflow builds the image and applies the proxy stack from the sui-operations ref it runs on.
    sui_operations_ref="${SUI_OPERATIONS_REF:-main}"
    printf 'Proxy stack configuration: sui-operations %s\n' "$sui_operations_ref"
    warn "Rolling a proxy that is serving takes the guardian's address down while it restarts, and drops the shares key provisioners have sent in a provisioning round that has not finished."
    if ! IFS= read -r -p "Roll the proxy of ${GUARDIAN_STACK##*/}? Type y/yes to continue: " roll_confirmation; then
      die "No input received; nothing was rolled."
    fi
    case "$roll_confirmation" in
      y | yes) ;;
      *) die "Not confirmed; nothing was rolled." ;;
    esac
    if ! run_url="$(gh workflow run hashi-guardian-proxy-deploy.yaml --repo MystenLabs/sui-operations \
      --ref "$sui_operations_ref" -f env="${GUARDIAN_STACK##*/}" -f hashi_commit="$HASHI_COMMIT")"; then
      die "Could not dispatch the proxy deploy."
    fi
    run_id="${run_url##*/}"
    [[ "$run_id" =~ ^[0-9]+$ ]] || die "Could not tell which run deploys the proxy: $run_url"
    printf 'Proxy deploy run: %s\n' "$run_url"
    run_or_die "The proxy deploy did not succeed." \
      gh run watch "$run_id" --repo MystenLabs/sui-operations --exit-status > /dev/null
    run_or_die "The proxy deployed but $GUARDIAN_PROXY_URL/health does not answer." \
      curl -fsS --max-time 15 -o /dev/null "$GUARDIAN_PROXY_URL/health"
    printf 'The proxy answers at %s.\n' "$GUARDIAN_PROXY_URL"
    ;;
  render)
    say "Render slot $SLOT's guardian configuration"
    require_guardian_build
    mkdir -p "$SLOT_DIR"
    render_into "$SLOT_DIR"
    # The guardian's own tools load both files as the ceremony will, when its build can. The
    # configuration lists certificates relative to its own directory.
    cd "$SLOT_DIR"
    tools_help="$(guardian_init tools --help)" || die "Could not build the guardian's tools."
    if [[ "$tools_help" == *check-config* ]]; then
      for rendered in guardian-init.yaml operator.yaml; do
        if ! guardian_init tools check-config --config "$rendered" > /dev/null; then
          rm -f -- "$OPERATOR_CONFIG"
          die "The guardian's tools refuse $SLOT_DIR/$rendered, so no step will run with it. Fix what they name, then render again."
        fi
      done
    else
      warn "This guardian's build has no tools check-config, so its tools have not checked the rendered files."
    fi
    printf 'Guardian commit:  %s\nPCR0:             %s\nLog bucket:       s3://%s\n' \
      "$HASHI_COMMIT" "$EIF_PCR0" "$GUARDIAN_BUCKET"
    printf 'Bitcoin network:  %s\nRetention class:  %s\nKey provisioners: %d, any %d provision\n' \
      "$BITCOIN_NETWORK" "$RETENTION_ENVIRONMENT" "${#CERTS[@]}" "$KP_THRESHOLD"
    printf 'For key provisioners: %s\nFor the operator:     %s\n' "$SLOT_DIR/guardian-init.yaml" "$OPERATOR_CONFIG"
    ;;
  publish)
    require_guardian_build
    require_fresh_render
    exec "$(dirname "$0")/publish-kp-config.sh" "$KP_NAME" "$SLOT_DIR" "$GUARDIAN_BUCKET"
    ;;
  tunnel)
    require_instance
    say "Forward $TUNNEL_ENDPOINT to slot $SLOT's guardian on $INSTANCE_ID"
    printf 'Leave this running in its own terminal while operator steps run.\n'
    exec aws ssm start-session --region "$REGION" --target "$INSTANCE_ID" \
      --document-name AWS-StartPortForwardingSession \
      --parameters "portNumber=3000,localPortNumber=$SLOT_PORT"
    ;;
  info)
    require_reached
    btc_key="$(hex_of "$(jq -r '.info.enclaveBtcPubkey // empty' <<< "$SLOT_INFO")")" \
      || die "Slot $SLOT's guardian reported a BTC key that is not base64."
    printf 'Slot:        %s, %s, on %s\nSigning key: %s\nBTC key:     %s\nLifecycle:   %s\n' \
      "$SLOT" "$SLOT_ROLE" "$INSTANCE_ID" "$SIGNING_KEY" "${btc_key:-none; the guardian is not provisioned}" \
      "$(lifecycle_of "$SLOT_INFO")"
    if [[ "$SLOT_ROLE" == active ]]; then
      printf 'Proxy:       fronts this guardian at %s\n' "$GUARDIAN_PROXY_URL"
      jq -r '"Serving:     " + (if .committeeEpoch then "committee epoch \(.committeeEpoch)" else "no; the guardian is not activated" end)' \
        <<< "$PROXY_INFO"
    else
      printf 'Relay:       sends key provisioners to this guardian at %s\n' "$GUARDIAN_PROXY_URL"
    fi
    ;;
  ceremony | provision | activate)
    require_guardian_build
    require_fresh_render
    # Another guardian's tunnel can be holding the local port.
    require_reached
    if [[ "$STEP" == ceremony ]]; then
      ceremonies="$(count_ceremonies)" || die "Could not list s3://$GUARDIAN_BUCKET/ceremony/."
      [[ "$ceremonies" == 0 ]] \
        || die "s3://$GUARDIAN_BUCKET already holds a completed key ceremony. A new guardian key needs a new s3-bucket-name."
      warn "The ceremony fixes three things for the life of the guardian's key: Bitcoin network $BITCOIN_NETWORK, retention class $RETENTION_ENVIRONMENT, and log bucket s3://$GUARDIAN_BUCKET."
      if ! IFS= read -r -p "Run the ceremony with them? Type y/yes to continue: " ceremony_confirmation; then
        die "No input received; the ceremony was not run."
      fi
      case "$ceremony_confirmation" in
        y | yes) ;;
        *) die "Not confirmed; the ceremony was not run." ;;
      esac
    fi
    # The configuration lists certificates relative to its own directory.
    cd "$SLOT_DIR"
    exec cargo run --release --locked --manifest-path "$REPO_ROOT/Cargo.toml" -p hashi-guardian-init -- \
      operator "$STEP" --config operator.yaml "$@"
    ;;
  new-session)
    require_instance
    say "Start a fresh guardian session on slot $SLOT, $INSTANCE_ID"
    SLOT_INFO="$(slot_info)" || die "$TUNNEL_DOWN"
    lifecycle="$(lifecycle_of "$SLOT_INFO")"
    # Restarting a ceremony session before it commits loses the ceremony.
    ceremonies="$(count_ceremonies)" || die "Could not list s3://$GUARDIAN_BUCKET/ceremony/."
    [[ "$ceremonies" =~ ^[1-9][0-9]*$ ]] \
      || die "s3://$GUARDIAN_BUCKET/ceremony/ holds no completed ceremony, so a fresh session would have no key to be provisioned with."
    case "$lifecycle" in
      ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS)
        [[ "${1:-}" == --abandon ]] \
          || die "Slot $SLOT's guardian has dealt shares that not every key provisioner has confirmed yet. Restarting it abandons that ceremony, and everyone who took part starts it again. To do that anyway: new-session $SLOT --abandon"
        warn "Abandoning slot $SLOT's ceremony."
        ;;
      ceremony/OPERATOR_INITIALIZED)
        warn "Slot $SLOT's guardian is initialized for a ceremony that has not dealt yet. Restarting it ends that session, so that step starts again."
        ;;
      withdraw/ACTIVATED)
        [[ "$STACK_SLOTS" != *$'\n'* ]] \
          || die "Slot $SLOT's guardian serves withdrawals while the stack has two slots. Move its key with the switchover step instead."
        warn "Slot $SLOT's guardian is serving withdrawals. Restarting it loses its key, and it serves nothing until a threshold of key provisioners provision it again."
        ;;
      *)
        warn "Restarting the enclave ends its session ($lifecycle). A guardian that holds its key loses it, and serves nothing until a threshold of key provisioners provision it again."
        ;;
    esac
    if ! IFS= read -r -p "Type $INSTANCE_ID to restart that guardian: " typed_id; then
      die "No input received; nothing was restarted."
    fi
    [[ "$typed_id" == "$INSTANCE_ID" ]] || die "Not confirmed; nothing was restarted."
    # Starting the enclave unit does not start the bridge that depends on it. is-active succeeds
    # when any one of several units is active, and the enclave unit is active while it retries.
    run_on_host "[\"systemctl restart hashi-guardian-enclave.service\",\"sleep 20\",\"systemctl start hashi-guardian-bridge.service\",\"for unit in $HOST_UNITS; do systemctl is-active --quiet \$unit || { echo \$unit is not active; exit 1; }; done\",\"nitro-cli describe-enclaves\",\"nitro-cli describe-enclaves | grep -q RUNNING\"]" \
      || die "The restart did not leave the enclave and its units running. Check the host step before going on."
    printf '\nGuardian restarted. Run the info step: its signing key must be new and its BTC key unset.\n'
    ;;
  *) die "Unknown step: $STEP. $USAGE" ;;
esac
