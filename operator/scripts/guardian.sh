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
STEPS="measure [slot] [run-id] | deploy | host [slot] | proxy | render [slot] | publish [slot] [rotate-kp-set] | tunnel [slot] | info [slot] | ceremony | new-session [slot] [--abandon] | provision [slot] [--do-genesis] | activate [slot] | arm <slot> | proxy-update | switchover <slot> | teardown <slot> | rotate-kp-set [slot] (init, submit <file>... or wait)"
GUARDIAN_UNIT_STATE='["if systemctl is-enabled --quiet hashi-guardian-enclave.service || systemctl is-active --quiet hashi-guardian-enclave.service; then echo GUARDIAN_RUNNING; else echo GUARDIAN_STOPPED; fi"]'

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

# Runs a JSON array of shell commands on a guardian host and prints their output.
run_on_host() {
  local instance_id="$1" command_id status=0
  if ! command_id="$(aws ssm send-command --region "$REGION" --instance-ids "$instance_id" \
    --document-name AWS-RunShellScript --query Command.CommandId --output text --parameters "commands=$2")"; then
    return 1
  fi
  aws ssm wait command-executed --region "$REGION" --command-id "$command_id" --instance-id "$instance_id" \
    || status=$?
  aws ssm get-command-invocation --region "$REGION" --command-id "$command_id" --instance-id "$instance_id" \
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

# sui-operations' workflows pin a Pulumi CLI, and a newer one can write state that CLI cannot read.
require_pulumi_version() {
  local written current
  written="$(pulumi -C "$1" stack export --stack "$GUARDIAN_STACK" | jq -r '.deployment.manifest.version // empty')" \
    || die "Could not read stack $GUARDIAN_STACK in $1."
  current="$(pulumi version)" || die "Could not read the Pulumi CLI's version."
  [[ -n "$written" && "$current" == "$written" ]] \
    || die "Stack $GUARDIAN_STACK in $1 was last written by Pulumi ${written:-unknown}, but this is Pulumi $current. Put Pulumi ${written:-the version sui-operations pins} first on your PATH."
}

# The sui-operations workflows that apply the guardian stacks would race a step applying them here.
require_no_guardian_runs() {
  local workflow status runs
  for workflow in hashi-guardian-proxy-deploy.yaml hashi-guardian-rotate.yaml; do
    for status in queued in_progress; do
      runs="$(gh run list --repo MystenLabs/sui-operations --workflow "$workflow" --status "$status" \
        --json databaseId --jq length)" || die "Could not list the runs of sui-operations' $workflow."
      [[ "$runs" == 0 ]] \
        || die "sui-operations' $workflow has a run $status, and it applies the guardian stacks too. Wait for it to finish."
    done
  done
}

confirm() {
  local answer
  if ! IFS= read -r -p "$1 Type y/yes to continue: " answer; then
    die "No input received; nothing was changed."
  fi
  case "$answer" in
    y | yes) ;;
    *) die "Not confirmed; nothing was changed." ;;
  esac
}

confirm_typed() {
  local typed
  if ! IFS= read -r -p "Type $1 $2: " typed; then
    die "No input received; nothing was changed."
  fi
  [[ "$typed" == "$1" ]] || die "Not confirmed; nothing was changed."
}

# Prints the state URN of the guardian instance with this ID.
instance_urn() {
  pulumi -C "$GUARDIAN_PULUMI_DIR" stack export --stack "$GUARDIAN_STACK" \
    | jq -r --arg id "$1" '.deployment.resources[]? | select(.type == "aws:ec2/instance:Instance" and .id == $id) | .urn'
}

# Prints a plan's resource changes as "<op> <urn>" lines, leaving out the stack's own outputs and
# reads, such as the proxy's reference to the enclave stack.
plan_changes() {
  jq -r '.steps[]? | select(.op != "same" and .op != "read" and .op != "refresh"
      and (.urn | contains("::pulumi:pulumi:Stack::") | not)) | "\(.op) \(.urn)"' <<< "$1"
}

# Previews an up of one guardian instance and what depends on it, prints it and sets PLAN_CHANGES. A
# target that names nothing is no error to Pulumi, so callers compare the changes with what they expect.
preview_slot() {
  local plan
  if ! plan="$(pulumi -C "$GUARDIAN_PULUMI_DIR" preview --stack "$GUARDIAN_STACK" --target "$1" --target-dependents --json)"; then
    # With --json, Pulumi reports what failed inside the plan it prints.
    jq -r '.diagnostics[]?.message // empty' <<< "$plan" >&2 || printf '%s\n' "$plan" >&2
    die "Could not preview stack $GUARDIAN_STACK."
  fi
  PLAN_CHANGES="$(plan_changes "$plan")"
  printf 'Plan for %s:\n%s\n' "$1" "${PLAN_CHANGES:-no resource changes}"
}

up_slot() {
  run_or_die "The update of stack $GUARDIAN_STACK did not finish. Run this step again: it previews the stack first." \
    pulumi -C "$GUARDIAN_PULUMI_DIR" up --stack "$GUARDIAN_STACK" --target "$1" --target-dependents --yes
}

# Applies the proxy stack from this worktree, so the proxy follows the guardian stack's slots. It never
# builds an image: the proxy step does.
update_proxy() {
  local relay lifecycle region cluster service desired_count running_count deployments task_definition running
  local configured plan changes unexpected urls backend standby
  # The relay holds a provisioning round's shares in memory, so a roll during one drops them.
  if relay="$(relay_info)"; then
    lifecycle="$(lifecycle_of "$relay")"
    case "$lifecycle" in
      withdraw/OPERATOR_INITIALIZED | ceremony/AWAITING_KEY_PROVISIONER_CONFIRMATIONS)
        die "The guardian the relay serves is in a key provisioner round ($lifecycle). Update the proxy once that round has finished."
        ;;
    esac
  else
    warn "The proxy's relay does not answer at $PROXY_AUTHORITY, so no key provisioner round runs through it."
  fi
  [[ -d "$PROXY_PULUMI_DIR" ]] || die "No guardian proxy Pulumi program at $PROXY_PULUMI_DIR."
  require_pulumi_version "$PROXY_PULUMI_DIR"
  configured="$(pulumi -C "$PROXY_PULUMI_DIR" config get hashi-guardian-proxy:proxy-image-tag --stack "$GUARDIAN_STACK")" \
    || die "Stack $GUARDIAN_STACK in $PROXY_PULUMI_DIR has no proxy-image-tag."
  region="$(pulumi -C "$PROXY_PULUMI_DIR" config get hashi-guardian-proxy:aws-region --stack "$GUARDIAN_STACK")" \
    || die "Stack $GUARDIAN_STACK in $PROXY_PULUMI_DIR has no aws-region."
  # The plan below comes from Pulumi's state, not a refresh, since a refresh would also act on drift
  # elsewhere in the stack, such as DNS records someone else manages. So read the service from ECS,
  # which also rolls a failed deployment back by itself.
  # shellcheck disable=SC2016
  if ! service="$(pulumi -C "$PROXY_PULUMI_DIR" stack export --stack "$GUARDIAN_STACK" \
    | jq -er '[.deployment.resources[]? | select(.type == "aws:ecs/service:Service") | .outputs | "\(.cluster) \(.name)"] | first')" \
    || ! read -r cluster service <<< "$service" \
    || ! read -r desired_count running_count deployments task_definition < <(aws ecs describe-services --region "$region" \
      --cluster "$cluster" --services "$service" --output text \
      --query 'services[0].[desiredCount, runningCount, length(deployments), deployments[?status==`PRIMARY`].taskDefinition | [0]]') \
    || ! running="$(aws ecs describe-task-definition --region "$region" --task-definition "$task_definition" \
      --query 'taskDefinition.containerDefinitions[?name==`proxy`].image | [0]' --output text)"; then
    die "Could not read the proxy service of stack $GUARDIAN_STACK from ECS."
  fi
  [[ "$desired_count" =~ ^[1-9][0-9]*$ && "$running_count" == "$desired_count" && "$deployments" == 1 ]] \
    || die "The proxy service runs ${running_count:-no} of ${desired_count:-no} tasks in ${deployments:-no} deployments. Wait for it to settle, or bring it back with a refreshed pulumi up of the proxy stack, before this step."
  [[ "${running##*:}" == "$configured" ]] \
    || die "The proxy runs $running, but $PROXY_PULUMI_DIR configures tag $configured. This step does not build images: roll a new proxy build with the proxy step."
  if ! plan="$(pulumi -C "$PROXY_PULUMI_DIR" preview --stack "$GUARDIAN_STACK" --json)"; then
    jq -r '.diagnostics[]?.message // empty' <<< "$plan" >&2 || printf '%s\n' "$plan" >&2
    die "Could not preview the proxy stack $GUARDIAN_STACK."
  fi
  changes="$(plan_changes "$plan")"
  if [[ -z "$changes" ]]; then
    printf 'The proxy already follows stack %s.\n' "$GUARDIAN_STACK"
    return 0
  fi
  printf 'Proxy plan:\n%s\n' "$changes"
  # Following the guardian slots changes only the task's guardian URLs, which replaces its definition
  # and points the service at the new one.
  unexpected="$(grep -vE '^(replace|create-replacement|delete-replaced|update) [^ ]*::aws:ecs/taskDefinition:TaskDefinition::|^update [^ ]*::aws:ecs/service:Service::' <<< "$changes" || true)"
  [[ -z "$unexpected" ]] \
    || die "The proxy plan changes more than its task definition and service. Nothing was changed; find out why first: $unexpected"
  if ! urls="$(jq -er '
      def proxy: fromjson | map(select(.name == "proxy")) | first;
      def guardian_urls: (.environment // []) | map(select(.name == "GUARDIAN_BACKEND_URL" or .name == "STANDBY_GUARDIAN_URL")) | from_entries;
      def without_urls: .environment |= ((. // []) | map(select(.name != "GUARDIAN_BACKEND_URL" and .name != "STANDBY_GUARDIAN_URL")) | sort_by(.name));
      [.steps[]? | select((.urn | contains("::aws:ecs/taskDefinition:TaskDefinition::"))
          and .oldState.inputs.containerDefinitions != null and .newState.inputs.containerDefinitions != null)
        | (.oldState.inputs.containerDefinitions | proxy) as $old | (.newState.inputs.containerDefinitions | proxy) as $new
        | select(($old | without_urls) == ($new | without_urls))
        | "\($new | guardian_urls | .GUARDIAN_BACKEND_URL // "")|\($new | guardian_urls | .STANDBY_GUARDIAN_URL // "")"]
      | if length == 1 then .[0] else error("not one comparable task definition") end' <<< "$plan")" \
    || ! IFS='|' read -r backend standby <<< "$urls" \
    || ! jq -e '[.steps[]? | select(.urn | contains("::aws:ecs/service:Service::")) | (.detailedDiff // {} | keys) - ["taskDefinition"] | length == 0] | all' \
      <<< "$plan" > /dev/null; then
    die "The proxy plan changes the proxy task by more than its guardian URLs, or could not be compared. Nothing was changed: read pulumi preview --diff for stack $GUARDIAN_STACK in $PROXY_PULUMI_DIR."
  fi
  [[ "$backend" == "http://$(output_value guardian_private_ip):3000" ]] \
    || die "The proxy plan sends nodes to $backend, not to the active guardian at $(output_value guardian_private_ip)."
  if [[ -n "$(output_value standby_private_ip)" ]]; then
    [[ "$standby" == "http://$(output_value standby_private_ip):3000" ]] \
      || die "The proxy plan relays key provisioners to ${standby:-no guardian}, not to the standby at $(output_value standby_private_ip)."
  else
    [[ -z "$standby" ]] || die "The proxy plan relays key provisioners to $standby, but stack $GUARDIAN_STACK has no standby."
  fi
  printf 'The proxy will send nodes to %s and key provisioners to %s.\n' "$backend" "${standby:-$backend}"
  warn "Updating the proxy restarts it: the guardian's address is down for some minutes, and nodes retry their requests."
  confirm "Update the proxy of stack $GUARDIAN_STACK?"
  run_or_die "The proxy update did not finish. Run this step again: it previews the proxy first." \
    pulumi -C "$PROXY_PULUMI_DIR" up --stack "$GUARDIAN_STACK" --yes
  run_or_die "The proxy updated but $GUARDIAN_PROXY_URL/health does not answer." \
    curl -fsS --max-time 15 -o /dev/null "$GUARDIAN_PROXY_URL/health"
}

# Prints a Sui GraphQL epoch's start, in seconds since the Unix epoch.
epoch_start() {
  jq -er '.data.epoch.startTimestamp | sub("\\.[0-9]+Z$"; "Z") | fromdateiso8601' <<< "$1"
}

# Stops unless the Sui epoch, and hashi's committee with it, stays put while guardians switch: a
# committee handoff that lands before activation leaves the new guardian a committee behind until the
# next epoch.
require_epoch_window() {
  local current previous epoch start previous_start now since remaining committee_epoch
  [[ -n "${SUI_GRAPHQL_URL:-}" ]] || die "$ENV_FILE does not set SUI_GRAPHQL_URL."
  if ! current="$(curl -fsS --max-time 15 -H 'Content-Type: application/json' \
    -d '{"query":"{ epoch { epochId startTimestamp } }"}' "$SUI_GRAPHQL_URL")" \
    || ! epoch="$(jq -er '.data.epoch.epochId' <<< "$current")" || ! start="$(epoch_start "$current")"; then
    die "Could not read the current Sui epoch from $SUI_GRAPHQL_URL."
  fi
  if ! previous="$(curl -fsS --max-time 15 -H 'Content-Type: application/json' \
    -d "{\"query\":\"{ epoch(epochId: $((epoch - 1))) { startTimestamp } }\"}" "$SUI_GRAPHQL_URL")" \
    || ! previous_start="$(epoch_start "$previous")"; then
    die "Could not read the previous Sui epoch from $SUI_GRAPHQL_URL."
  fi
  now="$(date +%s)"
  since=$((now - start))
  remaining=$((2 * start - previous_start - now))
  ((since >= 1800)) \
    || die "Sui epoch $epoch began $((since / 60)) minutes ago. Switch over once hashi's committee handoff has settled, 30 minutes after the epoch turns."
  ((remaining >= 3600)) \
    || die "Sui epoch $epoch ends in about $((remaining / 60)) minutes. Switch over after the next epoch has settled, so its committee handoff reaches the new guardian."
  committee_epoch="$(jq -r '.committeeEpoch // empty' <<< "$PROXY_INFO")"
  [[ "$committee_epoch" == "$epoch" ]] \
    || die "The serving guardian is at committee epoch ${committee_epoch:-none}, but Sui is at epoch $epoch. Wait for hashi's committee handoff to reach it."
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
  write_roster kp_roster "$ROSTER_THRESHOLD" "${ROSTER_CERTS[@]}"
  if ((${#NEW_ROSTER_CERTS[@]} > 0)); then
    printf '\n'
    write_roster new_kp_roster "$NEW_KP_THRESHOLD" "${NEW_ROSTER_CERTS[@]}"
  fi
  printf '\nlimiter_config:\n  refill_rate: %s\n  max_bucket_capacity: %s\n' "$REFILL_RATE" "$MAX_BUCKET_CAPACITY"
}

write_roster() {
  local name="$1" threshold="$2" cert
  shift 2
  printf '%s:\n  num_shares: %d\n  threshold: %d\n  kp_pgp_cert_paths:\n' "$name" "$#" "$threshold"
  for cert in "$@"; do
    printf '    - certs/%s\n' "$cert"
  done
}

# Copies a verified roster's certificates into a configuration directory's certs/ and sets ROSTER to
# their file names. A configuration lists two rosters by file name, so one name is one certificate.
copy_roster() {
  local roster_dir="$1" dir="$2" cert file
  [[ -f "$roster_dir/roster.txt" ]] || die "No verified roster in $roster_dir. Run download-kp-pubkeys.sh first."
  ROSTER=()
  for cert in "$roster_dir"/*/*-kp-pubkey.asc; do
    [[ -f "$cert" ]] || die "No certificates in $roster_dir."
    for file in "$cert" "${ATTESTATION_SUFFIXES[@]/#/${cert%.asc}.}"; do
      if [[ -e "$dir/certs/${file##*/}" ]] && ! cmp -s -- "$file" "$dir/certs/${file##*/}"; then
        die "${file##*/} differs between $KP_ROSTER_DIR and $NEW_KP_ROSTER_DIR. A key provisioner with a new certificate needs a new user ID."
      fi
    done
    cp -- "$cert" "${ATTESTATION_SUFFIXES[@]/#/${cert%.asc}.}" "$dir/certs/"
    ROSTER+=("${cert##*/}")
  done
}

# Writes guardian-init.yaml for the key provisioners and operator.yaml for the operator into a directory
# whose certs/ holds the rosters' certificates.
write_configs() {
  local dir="$1"
  write_config "$GUARDIAN_PROXY_URL" > "$dir/guardian-init.yaml"
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

# Writes the slot's configuration into a directory. Its own files list the roster that provisions
# guardians: the dealt one, or the new one once a KP-set rotation re-deals to it. A KP-set rotation's
# files, which list both, go in rotate-kp-set/.
render_into() {
  local dir="$1" other other_suffix="" dealt=()
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

  S3_ACCESS_KEY_ID="$(stack_output s3_access_key_id)" || die "Could not read the guardian's S3 access key."
  S3_SECRET_ACCESS_KEY="$(stack_output s3_secret_access_key --show-secrets)" \
    || die "Could not read the guardian's S3 secret key."

  rm -rf -- "$dir/certs" "$dir/rotate-kp-set"
  mkdir -p "$dir/certs"
  NEW_ROSTER_CERTS=()
  if [[ -z "$NEW_KP_ROSTER_DIR" ]]; then
    copy_roster "$KP_ROSTER_DIR" "$dir"
    ROSTER_CERTS=("${ROSTER[@]}")
    ROSTER_THRESHOLD="$KP_THRESHOLD"
    write_configs "$dir"
    return
  fi
  copy_roster "$NEW_KP_ROSTER_DIR" "$dir"
  ROSTER_CERTS=("${ROSTER[@]}")
  ROSTER_THRESHOLD="$NEW_KP_THRESHOLD"
  write_configs "$dir"
  mkdir -p "$dir/rotate-kp-set/certs"
  copy_roster "$KP_ROSTER_DIR" "$dir/rotate-kp-set"
  dealt=("${ROSTER[@]}")
  copy_roster "$NEW_KP_ROSTER_DIR" "$dir/rotate-kp-set"
  NEW_ROSTER_CERTS=("${ROSTER[@]}")
  ROSTER_CERTS=("${dealt[@]}")
  ROSTER_THRESHOLD="$KP_THRESHOLD"
  write_configs "$dir/rotate-kp-set"
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
    cmp -s "$WORK_DIR/$rendered" "$SLOT_DIR/$rendered" || stale+="${stale:+, }${rendered#./}"
  done < <(cd "$WORK_DIR" && find . -type f | sort)
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
      || die "The proxy fronts guardian ${proxy_key:-none}, but $TUNNEL_ENDPOINT reaches slot $SLOT's $SIGNING_KEY. The proxy caches its view for 30 seconds: run this step again. If they still differ, check that the tunnel is slot $SLOT's, then run the proxy-update step."
  else
    if ! RELAY_INFO="$(relay_info)" \
      || ! proxy_key="$(hex_of "$(jq -r '.signedInfo.data.signingPubKey // empty' <<< "$RELAY_INFO")")"; then
      die "The proxy's relay does not answer at $PROXY_AUTHORITY."
    fi
    [[ "$proxy_key" == "$SIGNING_KEY" ]] \
      || die "The proxy's relay sends key provisioners to guardian ${proxy_key:-none}, but $TUNNEL_ENDPOINT reaches slot $SLOT's $SIGNING_KEY. Check that the tunnel is slot $SLOT's, then run the proxy-update step."
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
NEW_KP_ROSTER_DIR="${NEW_KP_ROSTER_DIR:-}"
NEW_KP_THRESHOLD="${NEW_KP_THRESHOLD:-}"
[[ -z "$NEW_KP_ROSTER_DIR$NEW_KP_THRESHOLD" || (-n "$NEW_KP_ROSTER_DIR" && -n "$NEW_KP_THRESHOLD") ]] \
  || die "$ENV_FILE sets only one of NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD. Set both for a KP-set rotation, or neither."
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
PROXY_PULUMI_DIR="$(dirname "$GUARDIAN_PULUMI_DIR")/hashi-guardian-proxy"
case "$STEP" in
  deploy | proxy | proxy-update)
    [[ -z "$SLOT_ARG" ]] || die "The $STEP step acts on the whole stack, not one slot."
    ;;
  arm | switchover | teardown)
    [[ -n "$SLOT_ARG" ]] || die "Name the slot this step acts on: $STEP a or $STEP b."
    select_slot
    load_slot
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
      || die "Stack $GUARDIAN_STACK has two guardian slots. The deploy step runs an untargeted pulumi up, which can replace either guardian: use arm, switchover and teardown, as operator/rotate.md describes."
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
    host_report="$(run_on_host "$INSTANCE_ID" "[\"tail -n 12 /var/log/hashi-guardian-bootstrap.log\",\"grep -E '^\\\\[[^]]*\\\\] hashi-guardian user-data (complete|FAILED)' /var/log/hashi-guardian-bootstrap.log || echo 'The boot has not finished.'\",\"nitro-cli describe-enclaves\",\"systemctl is-active $HOST_UNITS || true\"]")" \
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
    printf 'Bitcoin network:  %s\nRetention class:  %s\n' "$BITCOIN_NETWORK" "$RETENTION_ENVIRONMENT"
    if ((${#NEW_ROSTER_CERTS[@]} > 0)); then
      # render_into leaves the rosters the re-deal's own files list: the dealt one and the new one.
      printf 'KP-set rotation:  %d key provisioners, any %d sign, re-deal to %d, any %d provision\n' \
        "${#ROSTER_CERTS[@]}" "$ROSTER_THRESHOLD" "${#NEW_ROSTER_CERTS[@]}" "$NEW_KP_THRESHOLD"
      printf 'For the signers:      %s\nFor the re-deal:      %s\n' \
        "$SLOT_DIR/rotate-kp-set/guardian-init.yaml" "$SLOT_DIR/rotate-kp-set/operator.yaml"
    else
      printf 'Key provisioners: %d, any %d provision\n' "${#ROSTER_CERTS[@]}" "$ROSTER_THRESHOLD"
    fi
    printf 'For key provisioners: %s\nFor the operator:     %s\n' "$SLOT_DIR/guardian-init.yaml" "$OPERATOR_CONFIG"
    ;;
  publish)
    config_dir="$SLOT_DIR"
    case "${1:-}" in
      "") ;;
      rotate-kp-set)
        [[ -n "$NEW_KP_ROSTER_DIR" ]] \
          || die "Set NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD in $ENV_FILE and render again to publish a KP-set rotation."
        config_dir="$SLOT_DIR/rotate-kp-set"
        ;;
      *) die "Usage: $0 <env-file> publish [slot] [rotate-kp-set]" ;;
    esac
    require_guardian_build
    require_fresh_render
    exec "$(dirname "$0")/publish-kp-config.sh" "$KP_NAME" "$config_dir" "$GUARDIAN_BUCKET"
    ;;
  rotate-kp-set)
    action="${1:-}"
    if (($# > 0)); then
      shift
    fi
    case "$action" in
      init | submit | wait) ;;
      *) die "Usage: $0 <env-file> rotate-kp-set [slot] init | submit <file>... | wait" ;;
    esac
    [[ -n "$NEW_KP_ROSTER_DIR" ]] \
      || die "Set NEW_KP_ROSTER_DIR and NEW_KP_THRESHOLD in $ENV_FILE, then render, for a KP-set rotation."
    [[ "$SLOT_ROLE" == standby ]] \
      || die "A KP-set rotation re-deals on a standby guardian, and slot $SLOT's is ${SLOT_ROLE/absent/not deployed}."
    require_guardian_build
    require_fresh_render
    require_reached
    submissions=()
    if [[ "$action" == submit ]]; then
      (($# > 0)) || die "Name the files the key provisioners sent: rotate-kp-set $SLOT submit <file>..."
      for file in "$@"; do
        [[ -f "$file" ]] || die "No submission file at $file."
        submissions+=(--submission "$(cd "$(dirname "$file")" && pwd -P)/${file##*/}")
      done
    else
      (($# == 0)) || die "rotate-kp-set $action takes no files."
    fi
    if [[ "$action" == init ]]; then
      lifecycle="$(lifecycle_of "$SLOT_INFO")"
      [[ "$lifecycle" == none || "$lifecycle" == ceremony/OPERATOR_INITIALIZED ]] \
        || die "Slot $SLOT's guardian is $lifecycle. A KP-set rotation needs a fresh guardian: start one with new-session $SLOT."
      warn "This makes slot $SLOT's guardian a ceremony guardian for good: it never serves withdrawals. Once the new key provisioners have all confirmed, start a fresh session on it with new-session $SLOT."
      confirm "Re-deal the key on slot $SLOT's guardian?"
    fi
    # The configuration lists certificates relative to its own directory.
    cd "$SLOT_DIR/rotate-kp-set"
    exec cargo run --release --locked --manifest-path "$REPO_ROOT/Cargo.toml" -p hashi-guardian-init -- \
      operator rotate-kp-set "$action" --config operator.yaml ${submissions[@]+"${submissions[@]}"}
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
    run_on_host "$INSTANCE_ID" "[\"systemctl restart hashi-guardian-enclave.service\",\"sleep 20\",\"systemctl start hashi-guardian-bridge.service\",\"for unit in $HOST_UNITS; do systemctl is-active --quiet \$unit || { echo \$unit is not active; exit 1; }; done\",\"nitro-cli describe-enclaves\",\"nitro-cli describe-enclaves | grep -q RUNNING\"]" \
      || die "The restart did not leave the enclave and its units running. Check the host step before going on."
    printf '\nGuardian restarted. Run the info step: its signing key must be new and its BTC key unset.\n'
    ;;
  arm)
    read_bucket
    active="$(output_value active_slot)"
    active="${active:-a}"
    serving_instance="$(output_value enclave_instance_id)"
    say "Arm slot $SLOT next to slot $active's guardian"
    [[ "$SLOT_ROLE" == absent ]] || die "Slot $SLOT already runs a guardian, as the $SLOT_ROLE."
    require_pulumi_version "$GUARDIAN_PULUMI_DIR"
    require_no_guardian_runs
    [[ "$active" != "$SLOT" && -n "$serving_instance" ]] \
      || die "Slot $SLOT is the stack's active slot. arm adds a standby next to a serving guardian."
    slot_enabled "$SLOT" \
      || die "Enable slot $SLOT first: set slot-$SLOT-enabled to \"true\" in stack $GUARDIAN_STACK's Pulumi.<stack>.yaml."
    configured_active="$(config_value active-slot)"
    [[ "${configured_active:-a}" == "$active" ]] \
      || die "Stack $GUARDIAN_STACK configures active-slot ${configured_active:-a}, but slot $active is active. Set it back before arming."
    suffix=""
    active_suffix=""
    [[ "$SLOT" == a ]] || suffix="-b"
    [[ "$active" == a ]] || active_suffix="-b"
    # Rotating to a different build also needs every reader to allowlist both, which nothing renders yet.
    [[ "$(config_value "hashi-commit$suffix") $(config_value "eif-pcr0$suffix")" \
      == "$(config_value "hashi-commit$active_suffix") $(config_value "eif-pcr0$active_suffix")" ]] \
      || die "Give slot $SLOT slot $active's build: hashi-commit$suffix and eif-pcr0$suffix equal to hashi-commit$active_suffix and eif-pcr0$active_suffix."
    for key in eif-features eif-ceremony-mode; do
      [[ -z "$(config_value "$key$suffix")" && -z "$(config_value "$key$active_suffix")" ]] \
        || die "Stack $GUARDIAN_STACK sets $key for a slot. A real guardian builds with neither: unset it."
    done
    if ! rotation_tags="$(pulumi -C "$GUARDIAN_PULUMI_DIR" stack tag ls --stack "$GUARDIAN_STACK" --json \
      | jq -r 'keys[] | select(startswith("rotation:"))')"; then
      die "Could not list the tags of stack $GUARDIAN_STACK."
    fi
    [[ -z "$rotation_tags" ]] \
      || die "Stack $GUARDIAN_STACK has rotation tags from sui-operations' rotation scripts: ${rotation_tags//$'\n'/, }. This flow keeps rotation state in Pulumi.<stack>.yaml, so clear them once you know the yaml says the same."
    if ! PROXY_INFO="$(curl -fsS --max-time 15 "$GUARDIAN_PROXY_URL/info")" \
      || [[ -z "$(jq -r '.committeeEpoch // empty' <<< "$PROXY_INFO")" ]]; then
      die "The proxy at $GUARDIAN_PROXY_URL serves no activated guardian. Arm a standby only next to one."
    fi
    if ! serving_urn="$(instance_urn "$serving_instance")" || [[ -z "$serving_urn" ]]; then
      die "Could not find slot $active's instance $serving_instance in stack $GUARDIAN_STACK's state."
    fi
    urn="${serving_urn%::*}::hashi-guardian-enclave-$SLOT"
    preview_slot "$urn"
    [[ "$PLAN_CHANGES" == "create $urn" ]] \
      || die "Arming slot $SLOT must create its instance and change nothing else, but this plan does not. Nothing was changed."
    confirm "Create slot $SLOT's guardian host?"
    up_slot "$urn"
    load_stack
    [[ "$(output_value enclave_instance_id)" == "$serving_instance" && "$(output_value active_slot)" == "$active" ]] \
      || die "Stack $GUARDIAN_STACK no longer shows slot $active's guardian $serving_instance as active. Check its outputs before going on."
    standby_instance="$(output_value standby_instance_id)"
    [[ -n "$standby_instance" ]] || die "Stack $GUARDIAN_STACK lists no standby after arming slot $SLOT. Check its outputs."
    printf '\nArmed slot %s on %s. The host builds the enclave image at boot; follow it with: host %s. Then run proxy-update, so the relay reaches it.\n' \
      "$SLOT" "$standby_instance" "$SLOT"
    ;;
  proxy-update)
    say "Update the proxy of stack $GUARDIAN_STACK to follow its guardian slots"
    require_no_guardian_runs
    update_proxy
    printf 'The proxy answers at %s.\n' "$GUARDIAN_PROXY_URL"
    ;;
  switchover)
    read_bucket
    other=b
    [[ "$SLOT" == a ]] || other=a
    if [[ "$(output_value active_slot)" != "$SLOT" ]]; then
      say "Check slot $SLOT's guardian is ready to serve"
      [[ "$SLOT_ROLE" == standby ]] || die "Slot $SLOT runs no standby guardian to switch over to."
      require_guardian_build
      require_fresh_render
      require_reached
      lifecycle="$(lifecycle_of "$SLOT_INFO")"
      [[ "$lifecycle" == withdraw/PROVISIONER_INITIALIZED ]] \
        || die "Slot $SLOT's guardian is $lifecycle, not provisioned and waiting for activation."
      standby_btc="$(hex_of "$(jq -r '.info.enclaveBtcPubkey // empty' <<< "$SLOT_INFO")")" \
        || die "Slot $SLOT's guardian reported a BTC key that is not base64."
      PROXY_INFO="$(curl -fsS --max-time 15 "$GUARDIAN_PROXY_URL/info")" \
        || die "The proxy does not answer at $GUARDIAN_PROXY_URL/info."
      serving_btc="$(jq -r '.btcPubkey // empty' <<< "$PROXY_INFO")"
      [[ -n "$standby_btc" && "$standby_btc" == "$serving_btc" ]] \
        || die "Slot $SLOT's guardian holds BTC key ${standby_btc:-none}, but the serving guardian holds ${serving_btc:-none}."
      serving_key="$(jq -r '.signingPubKey // empty' <<< "$PROXY_INFO")"
      [[ "$serving_key" =~ ^[0-9a-f]{64}$ ]] || die "The proxy's /info names no serving guardian's signing key."
      # Activation drops the configuration hash from a guardian's own report, so read it from the log.
      # A session is named by the start of its signing key.
      if ! serving_config="$(aws s3 cp --only-show-errors --region "$REGION" \
        "s3://$GUARDIAN_BUCKET/init/${serving_key:0:16}/02-oi-guardian-info.json" - \
        | jq -er '.message.Init.OIGuardianInfo.mode.Withdraw.config_hash')"; then
        die "Could not read the serving guardian's configuration hash from s3://$GUARDIAN_BUCKET/init/${serving_key:0:16}/."
      fi
      if ! standby_config="$(hex_of "$(jq -r '.info.configHash // empty' <<< "$SLOT_INFO")")" \
        || [[ -z "$standby_config" || "$standby_config" != "$serving_config" ]]; then
        die "Slot $SLOT's guardian has config hash ${standby_config:-none}, but the serving guardian has $serving_config. Their limiter or deployment block differ, and switching over would change them."
      fi
      require_pulumi_version "$GUARDIAN_PULUMI_DIR"
      require_no_guardian_runs
      require_epoch_window
      [[ "$(config_value active-slot)" == "$SLOT" ]] \
        || die "Set active-slot to $SLOT in stack $GUARDIAN_STACK's Pulumi.<stack>.yaml first, and commit it."
      # Nothing may need a build once the old guardian is stopped.
      run_or_die "Could not build hashi-guardian-init." \
        cargo build --release --locked --quiet --manifest-path "$REPO_ROOT/Cargo.toml" -p hashi-guardian-init

      say "Make slot $SLOT the stack's active slot"
      old_instance="$(output_value enclave_instance_id)"
      if ! urn="$(instance_urn "$INSTANCE_ID")" || [[ -z "$urn" ]]; then
        die "Could not find slot $SLOT's instance $INSTANCE_ID in stack $GUARDIAN_STACK's state."
      fi
      preview_slot "$urn"
      [[ -z "$PLAN_CHANGES" ]] \
        || die "Flipping the active slot must change no resource, but this plan does. Nothing was changed."
      warn "From here until activation, nodes' new withdrawals fail and are retried. Until the old guardian stops, setting active-slot back undoes this."
      confirm "Make slot $SLOT the active slot?"
      up_slot "$urn"
      load_stack
      # A target that names nothing applies cleanly too, so check the flip happened before relying on it.
      [[ "$(output_value active_slot)" == "$SLOT" && "$(output_value enclave_instance_id)" == "$INSTANCE_ID" \
        && "$(output_value standby_instance_id)" == "$old_instance" ]] \
        || die "Stack $GUARDIAN_STACK's outputs did not flip to slot $SLOT. Nothing else was changed: check its outputs."
      load_slot
    fi
    SLOT_INFO="$(slot_info)" || die "$TUNNEL_DOWN"
    if ! SIGNING_KEY="$(hex_of "$(jq -r '.info.signingPubKey // empty' <<< "$SLOT_INFO")")" \
      || ! slot_btc="$(hex_of "$(jq -r '.info.enclaveBtcPubkey // empty' <<< "$SLOT_INFO")")" \
      || [[ -z "$SIGNING_KEY" || -z "$slot_btc" ]]; then
      die "Slot $SLOT's guardian did not report its signing and BTC keys at $TUNNEL_ENDPOINT."
    fi
    old_instance="$(output_value standby_instance_id)"

    if ! PROXY_INFO="$(curl -fsS --max-time 15 "$GUARDIAN_PROXY_URL/info")" \
      || [[ "$(jq -r '.signingPubKey // empty' <<< "$PROXY_INFO")" != "$SIGNING_KEY" ]]; then
      say "Point the proxy at slot $SLOT's guardian"
      update_proxy
      # /info is cached for 30 seconds.
      fronted=""
      for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        if PROXY_INFO="$(curl -fsS --max-time 15 "$GUARDIAN_PROXY_URL/info")" \
          && [[ "$(jq -r '.signingPubKey // empty' <<< "$PROXY_INFO")" == "$SIGNING_KEY" ]]; then
          fronted=yes
          break
        fi
        sleep 10
      done
      [[ -n "$fronted" ]] \
        || die "The proxy does not front slot $SLOT's guardian two minutes after its update. The old guardian still runs: check the proxy before going on."
    fi

    if [[ -n "$old_instance" ]]; then
      unit_state="$(run_on_host "$old_instance" "$GUARDIAN_UNIT_STATE")" \
        || die "Could not read slot $other's host $old_instance."
      if [[ "$unit_state" == *GUARDIAN_RUNNING* ]]; then
        say "Stop slot $other's guardian"
        # The relay still reaches the old guardian, the last check that both hold one key.
        if ! old_info="$(relay_info)" \
          || ! old_btc="$(hex_of "$(jq -r '.signedInfo.data.enclaveBtcPubkey // empty' <<< "$old_info")")" \
          || [[ "$old_btc" != "$slot_btc" ]]; then
          die "Could not confirm through the relay that slot $other's guardian holds slot $SLOT's BTC key $slot_btc. Nothing was stopped."
        fi
        warn "Stopping slot $other's guardian on $old_instance cannot be undone: its copy of the key is gone, and only slot $SLOT's guardian holds it in memory after this."
        confirm_typed "$old_instance" "to stop slot $other's guardian for good"
        run_on_host "$old_instance" "[\"systemctl disable --now hashi-guardian-enclave.service hashi-guardian-bridge.service\",\"if systemctl is-enabled --quiet hashi-guardian-enclave.service || systemctl is-active --quiet hashi-guardian-enclave.service; then echo the enclave unit is still enabled or active; exit 1; fi\",\"if nitro-cli describe-enclaves | grep -q EnclaveID; then echo an enclave still runs; exit 1; fi\"]" \
          || die "Stopping slot $other's guardian did not finish. Run this step again: it checks the host first."
        printf 'Stopped slot %s guardian on %s.\n' "$other" "$old_instance"
      fi
    fi

    if [[ "$(lifecycle_of "$SLOT_INFO")" != withdraw/ACTIVATED ]]; then
      say "Activate slot $SLOT's guardian"
      printf 'It waits until every other guardian session has been quiet for ten minutes, and prints little until then.\n'
      require_guardian_build
      require_fresh_render
      # The activation waits on S3 for up to 15 minutes and then calls the guardian, so the tunnel's
      # 20 idle minutes must start now.
      slot_info > /dev/null || die "$TUNNEL_DOWN"
      activate_status=0
      (cd "$SLOT_DIR" && cargo run --release --locked --manifest-path "$REPO_ROOT/Cargo.toml" -p hashi-guardian-init -- \
        operator activate --config operator.yaml) || activate_status=$?
      SLOT_INFO="$(slot_info)" || die "$TUNNEL_DOWN"
      [[ "$(lifecycle_of "$SLOT_INFO")" == withdraw/ACTIVATED ]] \
        || die "Slot $SLOT's guardian is not activated. Run this step again: it resumes with activation."
      # Its post-check compares limiter state, which a withdrawal signed right after activation changes.
      ((activate_status == 0)) \
        || warn "operator activate exited with status $activate_status, but slot $SLOT's guardian reports itself activated."
    fi

    say "Check the proxy serves slot $SLOT's guardian"
    serving=""
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
      if PROXY_INFO="$(curl -fsS --max-time 15 "$GUARDIAN_PROXY_URL/info")" \
        && jq -e --arg key "$SIGNING_KEY" --arg btc "$slot_btc" --arg commit "$HASHI_COMMIT" \
          '.signingPubKey == $key and .btcPubkey == $btc and .gitRevision == $commit and .committeeEpoch != null' \
          <<< "$PROXY_INFO" > /dev/null; then
        serving=yes
        break
      fi
      sleep 10
    done
    [[ -n "$serving" ]] || die "The proxy's /info does not show slot $SLOT's activated guardian: ${PROXY_INFO:-no answer}"
    jq -r '"Serving:     slot '"$SLOT"', committee epoch \(.committeeEpoch), BTC key \(.btcPubkey)"' <<< "$PROXY_INFO"
    printf 'Once it has served for a while, tear down slot %s: teardown %s.\n' "$other" "$other"
    ;;
  teardown)
    require_instance
    say "Tear down slot $SLOT's guardian host $INSTANCE_ID"
    [[ "$SLOT_ROLE" == standby ]] || die "Slot $SLOT runs the active guardian. Only a standby can be torn down."
    require_pulumi_version "$GUARDIAN_PULUMI_DIR"
    require_no_guardian_runs
    ! slot_enabled "$SLOT" \
      || die "Disable slot $SLOT first: set slot-$SLOT-enabled to \"false\" in stack $GUARDIAN_STACK's Pulumi.<stack>.yaml, and commit it."
    active="$(output_value active_slot)"
    configured_active="$(config_value active-slot)"
    [[ "${configured_active:-a}" == "$active" ]] \
      || die "Stack $GUARDIAN_STACK configures active-slot ${configured_active:-a}, but slot $active is active."
    if ! PROXY_INFO="$(curl -fsS --max-time 15 "$GUARDIAN_PROXY_URL/info")" \
      || [[ -z "$(jq -r '.committeeEpoch // empty' <<< "$PROXY_INFO")" ]]; then
      die "The proxy at $GUARDIAN_PROXY_URL serves no activated guardian. Tear nothing down until one serves."
    fi
    unit_state="$(run_on_host "$INSTANCE_ID" "$GUARDIAN_UNIT_STATE")" || die "Could not read slot $SLOT's host."
    if [[ "$unit_state" != *GUARDIAN_STOPPED* ]]; then
      # A retiring guardian still signs until the switchover step stops it; a standby never has.
      SLOT_INFO="$(slot_info)" || die "$TUNNEL_DOWN"
      lifecycle="$(lifecycle_of "$SLOT_INFO")"
      [[ "$lifecycle" != withdraw/ACTIVATED ]] \
        || die "Slot $SLOT's guardian on $INSTANCE_ID is activated and still runs. Stop it with the switchover step first."
      warn "Slot $SLOT's guardian still runs ($lifecycle). Tearing it down abandons it: what was provisioned or dealt to it is lost."
    fi
    if ! urn="$(instance_urn "$INSTANCE_ID")" || [[ -z "$urn" ]]; then
      die "Could not find slot $SLOT's instance $INSTANCE_ID in stack $GUARDIAN_STACK's state."
    fi
    preview_slot "$urn"
    [[ "$PLAN_CHANGES" == "delete $urn" ]] \
      || die "Tearing down slot $SLOT must delete its instance and change nothing else, but this plan does not. Nothing was changed."
    confirm_typed "$INSTANCE_ID" "to destroy slot $SLOT's host"
    up_slot "$urn"
    load_stack
    [[ -z "$(output_value standby_instance_id)" && "$(output_value active_slot)" == "$active" ]] \
      || die "Stack $GUARDIAN_STACK's outputs do not show slot $active alone. Check them before going on."
    printf '\nTore down slot %s. Run proxy-update, so the relay stops pointing at it.\n' "$SLOT"
    ;;
  *) die "Unknown step: $STEP. $USAGE" ;;
esac
