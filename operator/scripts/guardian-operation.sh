#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SCRIPT_DIR="$(dirname "$0")"
FLOWS=(provision rotate rotate-kp-set)

say() {
  printf '\n== %s ==\n' "$1"
}

die() {
  printf '\nERROR: %s\n' "$1" >&2
  exit 1
}

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
    cargo) printf '%s' "Rust toolchain (rustup)" ;;
    git | jq) printf '%s' "$1" ;;
    shasum) printf '%s' "standard system utilities" ;;
  esac
}

# Each line is "<step> <kind> <argument> <description>". The kind is `enclave` for a step that
# changes the deployment, which only the sui-operations driver may run, or `packet` for a step
# this repository owns.
steps_for_flow() {
  case "$1" in
    provision)
      cat << 'STEPS'
measure enclave measure Measure the ceremony and withdraw builds, and record both PCR0s
deploy-ceremony enclave deploy-ceremony Deploy the ceremony-mode enclave on a fresh bucket
proxy enclave proxy Put the proxy in front of the ceremony enclave
publish-ceremony packet ceremony Publish the ceremony packet for every key provisioner
ceremony enclave ceremony Run operator ceremony and wait for every key provisioner
ceremony-result enclave ceremony-result Record the guardian BTC public key
flip-withdraw enclave flip-withdraw Replace the instance with the withdraw-mode enclave
proxy-withdraw enclave proxy Point the proxy at the withdraw-mode enclave
provision enclave provision Run operator provision and print the session and config hash
publish-provision packet provision-genesis Publish the provisioning packet for the key provisioners
wait-kps enclave wait-kps Wait until the enclave has reconstructed the ceremony key
activate enclave activate Activate the guardian behind the heartbeat fence
verify enclave verify Check the public endpoint serves the ceremony key
revoke packet revoke Revoke the key provisioners' access key
STEPS
      ;;
    rotate)
      cat << 'STEPS'
arm enclave rotate-arm Deploy the standby slot and route the relay to it
provision-standby enclave provision-standby Run operator provision on the standby, without genesis
publish-provision packet provision Publish the provisioning packet for the key provisioners
wait-kps enclave wait-kps Wait until the standby has reconstructed the ceremony key
switchover enclave rotate-switchover Flip the proxy, stop the old guardian, and activate
verify enclave verify Check the public endpoint serves the ceremony key
teardown enclave rotate-teardown Destroy the retired slot
revoke packet revoke Revoke the key provisioners' access key
STEPS
      ;;
    rotate-kp-set)
      cat << 'STEPS'
roster enclave rotate-kp-set-roster Record the proposed new key provisioner set
deploy enclave rotate-kp-set-deploy Deploy the standby slot as a ceremony enclave
init enclave rotate-kp-set-init Operator-initialize it and print the proposal
publish-rotate packet rotate-kp-set Publish the signing packet for the current key provisioners
collect packet collect Download the current key provisioners' signed submissions
publish-ceremony packet ceremony Publish the ceremony packet for the new key provisioners
submit enclave rotate-kp-set-submit Submit the batch and wait for every new key provisioner
result enclave rotate-kp-set-result Adopt the new set as the dealt roster
revoke packet revoke Revoke the key provisioners' access key
STEPS
      ;;
  esac
}

USAGE="Usage: $0 <flow> <name> [step] [--done], where <flow> is one of: ${FLOWS[*]}"
FLOW=""
NAME=""
STEP=""
RECORD_ONLY=false
for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "$USAGE" \
        "Walks one guardian operation step by step, publishing packets for the key provisioners and" \
        "handing every deployment step to the sui-operations guardian driver. Without a step, it" \
        "prints the steps and which one comes next. --done records a step run elsewhere." \
        "See operator/README.md."
      exit 0
      ;;
    --done)
      RECORD_ONLY=true
      ;;
    *)
      if [[ -z "$FLOW" ]]; then
        FLOW="$argument"
      elif [[ -z "$NAME" ]]; then
        NAME="$argument"
      elif [[ -z "$STEP" ]]; then
        STEP="$argument"
      else
        die "Unexpected argument: $argument. $USAGE"
      fi
      ;;
  esac
done
flow_known=false
for known_flow in "${FLOWS[@]}"; do
  if [[ "$FLOW" == "$known_flow" ]]; then
    flow_known=true
  fi
done
[[ "$flow_known" == true ]] || die "Unknown flow: ${FLOW:-none}. $USAGE"
name_pattern='^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
if [[ ! "$NAME" =~ $name_pattern ]] || ((${#NAME} > 39)); then
  die "$USAGE, where <name> has at most 39 lowercase letters, digits, and inner hyphens."
fi

required_commands=(aws cargo git jq shasum)
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

RUN_DIR="$REPO_ROOT/.hashi/guardian-runs/$FLOW-$NAME"
DONE_FILE="$RUN_DIR/completed"
mkdir -p "$RUN_DIR"
touch "$DONE_FILE"

steps_for_flow "$FLOW" > "$RUN_DIR/steps"
NEXT_STEP=""
while read -r step _; do
  if [[ -z "$NEXT_STEP" ]] && ! grep -qxF -- "$step" "$DONE_FILE"; then
    NEXT_STEP="$step"
  fi
done < "$RUN_DIR/steps"

if [[ -z "$STEP" ]]; then
  say "Guardian $FLOW: $NAME"
  while read -r step kind _ description; do
    marker="  "
    if grep -qxF -- "$step" "$DONE_FILE"; then
      marker="ok"
    elif [[ "$step" == "$NEXT_STEP" ]]; then
      marker="->"
    fi
    printf '%s  %-18s %-8s %s\n' "$marker" "$step" "$kind" "$description"
  done < "$RUN_DIR/steps"
  if [[ -z "$NEXT_STEP" ]]; then
    printf '\nEvery step is done. Run state: %s\n' "$RUN_DIR"
    exit 0
  fi
  printf '\nNext:\n  %s %s %s %s\n' "$0" "$FLOW" "$NAME" "$NEXT_STEP"
  exit 0
fi

STEP_KIND=""
STEP_ARGUMENT=""
STEP_DESCRIPTION=""
while read -r step kind argument description; do
  if [[ "$step" == "$STEP" ]]; then
    STEP_KIND="$kind"
    STEP_ARGUMENT="$argument"
    STEP_DESCRIPTION="$description"
  fi
done < "$RUN_DIR/steps"
[[ -n "$STEP_KIND" ]] || die "The $FLOW flow has no step $STEP. Run without a step to see them."
if grep -qxF -- "$STEP" "$DONE_FILE"; then
  die "Step $STEP is already done. Remove its line from $DONE_FILE to run it again."
fi
# Out-of-order steps are how a rotation loses a guardian, so the order is the runbook.
[[ "$STEP" == "$NEXT_STEP" ]] \
  || die "The next step is $NEXT_STEP, not $STEP. Run without a step to see where this operation is."

say "Guardian $FLOW: $STEP"
printf '%s\n' "$STEP_DESCRIPTION"

if [[ "$RECORD_ONLY" == true ]]; then
  printf '%s\n' "$STEP" >> "$DONE_FILE"
  printf '\nRecorded as done without running it here.\n'
# Every step that changes the deployment belongs to the sui-operations driver: it asserts each
# pulumi plan and targets one slot. Point HASHI_GUARDIAN_DRIVER at the copy for this environment.
elif [[ "$STEP_KIND" == enclave ]]; then
  driver="${HASHI_GUARDIAN_DRIVER:-}"
  printf '\nThis step changes the deployment. It runs in sui-operations:\n  %s %s\n' \
    "${driver:-<sui-operations>/scripts/hashi/guardian-driver/operator.sh}" "$STEP_ARGUMENT"
  if [[ -n "$driver" ]]; then
    [[ -x "$driver" ]] || die "HASHI_GUARDIAN_DRIVER is not an executable file: $driver"
    if ! IFS= read -r -p "Run it now? Type y/yes to continue: " run_confirmation; then
      die "No input received; nothing was run."
    fi
    case "$run_confirmation" in
      y | yes)
        "$driver" "$STEP_ARGUMENT"
        printf '%s\n' "$STEP" >> "$DONE_FILE"
        ;;
      *) die "The step was not confirmed and was not run." ;;
    esac
  else
    printf '\nRun it there, then record it here with:\n  %s %s %s %s --done\n' \
      "$0" "$FLOW" "$NAME" "$STEP"
    exit 0
  fi
else
  case "$STEP_ARGUMENT" in
    revoke)
      "$SCRIPT_DIR/revoke-kp-packet-key.sh" "$NAME"
      ;;
    collect)
      "$SCRIPT_DIR/download-kp-submissions.sh" "$NAME" "$RUN_DIR/submissions"
      ;;
    *)
      bundle="$RUN_DIR/bundle-$STEP_ARGUMENT"
      if [[ ! -d "$bundle" ]]; then
        printf '\nRender the %s bundle first, in sui-operations:\n  %s bundle %s %s\n' \
          "$STEP_ARGUMENT" \
          "${HASHI_GUARDIAN_DRIVER:-<sui-operations>/scripts/hashi/guardian-driver/operator.sh}" \
          "$STEP_ARGUMENT" "$bundle"
        die "No bundle at $bundle."
      fi
      "$SCRIPT_DIR/publish-kp-packet.sh" "$NAME" "$STEP_ARGUMENT" "$bundle"
      ;;
  esac
  printf '%s\n' "$STEP" >> "$DONE_FILE"
fi

NEXT_STEP=""
while read -r step _; do
  if [[ -z "$NEXT_STEP" ]] && ! grep -qxF -- "$step" "$DONE_FILE"; then
    NEXT_STEP="$step"
  fi
done < "$RUN_DIR/steps"
say "Step complete"
if [[ -z "$NEXT_STEP" ]]; then
  printf 'Guardian %s finished! Run state: %s\n' "$FLOW" "$RUN_DIR"
else
  printf 'Next:\n  %s %s %s %s\n' "$0" "$FLOW" "$NAME" "$NEXT_STEP"
fi
