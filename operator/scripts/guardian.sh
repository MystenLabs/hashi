#!/usr/bin/env bash
# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# The operator's half of a guardian key lifetime: provisioning a new guardian,
# rotating the guardian, and rotating the key provisioner set. One step per
# invocation, every step re-runnable.
#
# The key provisioners' half is key-provisioner/scripts/run-guardian-step.sh,
# driven by the packets this script renders.

set -euo pipefail
# Keep parsed CLI output stable regardless of the user's locale.
export LC_ALL=C
export AWS_PAGER=""
export AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SCRIPT_DIR="$(dirname "$0")"
# shellcheck source=operator/scripts/guardian-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/guardian-lib.sh"

USAGE="Usage: $0 <env> <step> [arguments]"
HELP=(
  "$USAGE"
  ""
  "Looking"
  "  status                         the stack, both slots, the roster, and what the guardian reports"
  ""
  "Provisioning a new guardian"
  "  measure <ceremony|withdraw>    measure a build in CI and record its PCR0 on the stack"
  "  deploy-ceremony                deploy the ceremony enclave on a fresh bucket and key lifetime"
  "  proxy                          roll the proxy onto whatever the enclave stack now exports"
  "  packet <phase> <name>          render and publish the packet for that step"
  "  ceremony                       run operator ceremony and wait for every key provisioner"
  "  flip-withdraw [slot]           replace the slot's instance with the withdraw-mode enclave"
  "  provision [--genesis]          run operator provision and print what to tell the KPs"
  "  wait-kps [slot]                wait until the enclave has reconstructed the ceremony key"
  "  activate [slot]                activate the guardian behind the heartbeat fence"
  "  verify                         the public endpoint serves the ceremony key"
  ""
  "Rotating the guardian"
  "  arm                            deploy the standby slot and route the relay to it"
  "  switchover                     flip the proxy, stop the old guardian, and activate"
  "  teardown                       destroy the retired slot"
  ""
  "Rotating the key provisioner set"
  "  rotate-kp-set init             operator-initialize the rotation's ceremony enclave"
  "  rotate-kp-set submit           submit the collected signatures and wait for the new KPs"
  "  rotate-kp-set result           adopt the new set as the dealt roster"
  ""
  "Configuration comes from .hashi/guardian.env; see operator/guardian.env.sample."
)

for argument in "$@"; do
  case "$argument" in
    -h | --help)
      printf '%s\n' "${HELP[@]}"
      exit 0
      ;;
  esac
done

ENV_NAME="${1:-}"
STEP="${2:-}"
[[ -n "$ENV_NAME" && -n "$STEP" ]] || die "$USAGE"
shift 2

command_package() {
  case "$1" in
    aws) printf '%s' "AWS CLI v2" ;;
    cargo) printf '%s' "Rust toolchain (rustup)" ;;
    gh) printf '%s' "GitHub CLI" ;;
    jq | lsof | pulumi) printf '%s' "$1" ;;
  esac
}

required_commands=(aws cargo gh jq lsof pulumi)
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

trap close_tunnels EXIT
load_config "$ENV_NAME"

# Every step says which guardian it is about to act on, before it acts.
say "Guardian $GUARDIAN_ENV: $STEP"
if ! identity="$(aws sts get-caller-identity --query '[Account, Arn]' --output text)"; then
  die "Could not read the AWS identity. Log in first, for example: aws sso login --profile admin"
fi
read -r ACCOUNT ARN <<< "$identity"
note "stack        $STACK"
note "aws account  $ACCOUNT"
note "aws identity $ARN"
note "relay        $RELAY"

# The tunnel a phase talks to its own slot over. Operator RPCs never go through
# the proxy: it denies them.
slot_endpoint() {
  printf 'http://127.0.0.1:%s' "$(slot_port "$1")"
}

open_slot_tunnel() {
  local slot="$1" instance
  instance="$(slot_instance "$slot")"
  [[ -n "$instance" ]] || die "The stack exports no instance for slot $slot."
  note "slot $slot is $instance"
  open_tunnel "$instance" "$(slot_port "$slot")"
  wait_guardian "$(slot_endpoint "$slot")"
}

# Renders the operator's config into OPERATOR_CONFIG and shows what it says.
#
# It always carries the stack's static S3 key: OperatorInit installs whatever the
# operator resolved into the enclave for the life of the session, and temporary
# credentials would expire under it.
operator_config() {
  local phase="$1" slot="$2"
  OPERATOR_CONFIG="$RUN_DIR/operator-$phase.yaml"
  render_config "$OPERATOR_CONFIG" "$phase" "$(slot_endpoint "$slot")" "" static
  run_or_die "The rendered config is not one the guardian tools accept." \
    "$INIT_BIN" tools check-config --config "$OPERATOR_CONFIG"
}

case "$STEP" in
  status)
    init_build
    note "attestation  $(if attestation_is_mock; then printf mock; else printf real; fi)"
    note "bucket       s3://$(guardian_bucket)"
    note "active slot  $(active_slot)"
    for slot in a b; do
      instance="$(slot_instance "$slot")"
      [[ -n "$instance" ]] || continue
      printf '   slot %s       %s  commit %s  pcr0 %s…\n' "$slot" "$instance" \
        "$(slot_revision "$slot" | cut -c 1-12)" "$(slot_pcr0 "$slot" | cut -c 1-12)"
    done
    note "roster       $(roster_ids "$KP_ROSTER_DIR" | grep -c .) key provisioners, threshold $KP_THRESHOLD"
    roster_ids "$KP_ROSTER_DIR" | sed 's/^/     /'
    printf '\n'
    for field in lifecycle revision config-hash enclave-btc-pubkey; do
      printf '   relay %-20s %s\n' "$field" "$(fetch_field "$RELAY" "$field" || printf '(not available)')"
    done
    # The allowlist a packet pins comes from stack config, so config that has
    # moved past what is running would fail every key provisioner's check.
    serving_revision="$(fetch_field "$RELAY" revision || true)"
    if [[ -n "$serving_revision" && "$serving_revision" != "$(slot_revision "$(active_slot)")" ]]; then
      warn "The stack pins $(slot_revision "$(active_slot)") but the serving guardian reports $serving_revision. Deploy before rendering any packet."
    fi
    ;;

  measure)
    mode="${1:-}"
    case "$mode" in ceremony | withdraw) ;; *) die "Usage: $0 $ENV_NAME measure <ceremony|withdraw>" ;; esac
    if attestation_is_mock; then
      die "$STACK builds with non-enclave-dev, which reports an all-zero PCR0. There is nothing to measure."
    fi
    revision="${2:-$(slot_revision "$(active_slot)")}"
    confirm "Measure the $mode build of $revision for s3://$(guardian_bucket)?"
    dispatch_measurement "$mode" "$revision"
    note "dispatched; find the run with: gh run list --repo MystenLabs/hashi --workflow guardian-enclave.yml"
    note "then record it with: $0 $ENV_NAME record-pcr0 $mode <run id>"
    ;;

  record-pcr0)
    mode="${1:-}"
    run_id="${2:-}"
    [[ -n "$mode" && -n "$run_id" ]] || die "Usage: $0 $ENV_NAME record-pcr0 <ceremony|withdraw> <run id>"
    pcr0="$(measurement_pcr0 "$run_id")"
    note "both runners measured $pcr0"
    case "$mode" in
      ceremony)
        enclave_cfg_set ceremony-git-revision "$(slot_revision "$(active_slot)")"
        enclave_cfg_set ceremony-pcr0 "$pcr0"
        ;;
      withdraw)
        enclave_cfg_set "$(slot_key "$(active_slot)" eif-pcr0)" "$pcr0"
        ;;
      *) die "Usage: $0 $ENV_NAME record-pcr0 <ceremony|withdraw> <run id>" ;;
    esac
    note "recorded on $STACK"
    ;;

  render)
    phase="${1:-}"
    out_dir="${2:-}"
    [[ -n "$phase" && -n "$out_dir" ]] || die "Usage: $0 $ENV_NAME render <phase> <out-dir>"
    init_build
    rm -rf "$out_dir"
    mkdir -p "$out_dir/certs"
    roster_dir="$KP_ROSTER_DIR"
    [[ "$phase" != rotate-ceremony ]] || roster_dir="${NEW_KP_ROSTER_DIR:?}"
    while IFS= read -r cert; do
      cp -- "$cert" "${cert%.asc}".attestation-*.pem "$out_dir/certs/"
    done < <(roster_paths "$roster_dir")
    if [[ "$phase" == rotate-signer ]]; then
      while IFS= read -r cert; do
        cp -- "$cert" "${cert%.asc}".attestation-*.pem "$out_dir/certs/"
      done < <(roster_paths "${NEW_KP_ROSTER_DIR:?}")
    fi
    render_config "$out_dir/guardian-init.yaml" "$phase" "$RELAY" certs environment
    if ! (cd "$out_dir" && "$INIT_BIN" tools check-config --config guardian-init.yaml); then
      die "The rendered packet is not one the guardian tools accept."
    fi
    note "rendered $out_dir"
    ;;

  packet)
    phase="${1:-}"
    name="${2:-}"
    [[ -n "$phase" && -n "$name" ]] || die "Usage: $0 $ENV_NAME packet <phase> <packet-bucket-name>"
    slot="${3:-$(active_slot)}"
    case "$phase" in
      ceremony) render_phase=ceremony ;;
      provision | provision-genesis) render_phase="withdraw-$slot" ;;
      rotate-kp-set) render_phase=rotate-signer ;;
      *) die "Unknown packet phase: $phase" ;;
    esac
    bundle="$RUN_DIR/bundle-$phase"
    attestation=real
    if attestation_is_mock; then
      attestation=mock
    fi
    "$0" "$ENV_NAME" render "$render_phase" "$bundle"
    "$SCRIPT_DIR/publish-kp-packet.sh" "$name" "$phase" "$bundle" --attestation "$attestation"
    ;;

  deploy-ceremony)
    # The only untargeted update: it mints a fresh bucket and therefore a fresh
    # key lifetime. Every deposit address derived from the old key stops being
    # spendable by this guardian.
    [[ "$(enclave_cfg eif-ceremony-mode)" == true ]] \
      || die "Set eif-ceremony-mode to true on $STACK first; this step deploys a ceremony enclave."
    # One bucket per key lifetime: it is both key custody and the write-ahead log,
    # and a ceremony must never be dealt onto records from an earlier one.
    new_bucket="$(enclave_cfg s3-bucket-name)"
    [[ -n "$new_bucket" ]] || die "$STACK has no s3-bucket-name."
    if aws s3api head-bucket --bucket "$new_bucket" > /dev/null 2>&1; then
      die "s3://$new_bucket already exists, and a ceremony may not be dealt onto an earlier lifetime's records. Set hashi-guardian-enclave:s3-bucket-name to a name that does not exist yet."
    fi
    warn "This mints a NEW guardian key for $GUARDIAN_ENV and abandons the current one."
    note "new bucket   s3://$new_bucket"
    assert_plan '' '.' --diff
    confirm "Deploy a ceremony enclave and a fresh bucket on $STACK?"
    log="$RUN_DIR/logs/enclave-up-$(date -u +%Y%m%dT%H%M%SZ).log"
    run_or_die "The pulumi up failed; see $log" \
      pulumi_enclave up --yes --non-interactive > "$log" 2>&1
    grep -E "Resources:" "$log" | tail -2
    slot="$(active_slot)"
    wait_host_bootstrap "$(slot_instance "$slot")"
    ;;

  proxy)
    # The proxy relays every key provisioner submission and verifies their
    # attestations, so it has to be the commit the enclave is, not whatever was
    # pushed last. The tag is the image's identity: pushing a new build under an
    # existing tag leaves pulumi with no diff and ECS on the old task.
    deployed="$(slot_revision "$(active_slot)")"
    image_tag="$(pulumi_proxy config get hashi-guardian-proxy:proxy-image-tag 2> /dev/null || true)"
    [[ "$image_tag" == "$deployed" ]] \
      || die "The proxy stack pins proxy-image-tag '${image_tag:-none}', but the enclave runs $deployed. Set it with:
  pulumi -C $PROXY_DIR --stack $STACK config set hashi-guardian-proxy:proxy-image-tag $deployed"
    repository="hashi-guardian-proxy-$GUARDIAN_ENV"
    if ! aws ecr describe-images --repository-name "$repository" \
      --image-ids "imageTag=$image_tag" > /dev/null 2>&1; then
      [[ "$(git -C "$REPO_ROOT" rev-parse HEAD)" == "$deployed" ]] \
        || die "No $repository:$image_tag in ECR, and this checkout is not at $deployed. Check it out, then run this step again."
      registry="$(pulumi_proxy stack output ecr_repo_url)"
      [[ -n "$registry" ]] || die "The proxy stack exports no ecr_repo_url."
      confirm "Build and push $registry:$image_tag?"
      run_or_die "Could not build the proxy image." \
        docker buildx build --platform linux/amd64 --load \
        -f "$REPO_ROOT/docker/hashi-guardian-proxy/Containerfile" \
        -t "$registry:$image_tag" "$REPO_ROOT"
      aws ecr get-login-password | docker login --username AWS --password-stdin "${registry%%/*}" > /dev/null
      run_or_die "Could not push $registry:$image_tag." docker push "$registry:$image_tag"
    fi
    confirm "Roll the proxy for $GUARDIAN_ENV onto $image_tag?"
    pulumi_up_proxy
    ;;

  ceremony)
    init_build
    slot="$(active_slot)"
    open_slot_tunnel "$slot"
    operator_config ceremony "$slot"
    note "waiting for every key provisioner to confirm; this blocks until they do"
    "$INIT_BIN" operator ceremony --config "$OPERATOR_CONFIG"
    ;;

  flip-withdraw)
    slot="${1:-$(active_slot)}"
    enclave_cfg_set "$(slot_key "$slot" eif-ceremony-mode)" ""
    assert_urn_exists "$(slot_urn "$slot")"
    assert_plan '' 'to (replace|update)' --target "$(slot_urn "$slot")" --target-dependents
    confirm "Replace slot $slot with the withdraw-mode enclave?"
    pulumi_up_slot "$slot"
    wait_host_bootstrap "$(slot_instance "$slot")"
    ;;

  provision)
    genesis=()
    [[ "${1:-}" != --genesis ]] || genesis=(--do-genesis)
    init_build
    slot="$(active_slot)"
    open_slot_tunnel "$slot"
    operator_config "withdraw-$slot" "$slot"
    "$INIT_BIN" operator provision --config "$OPERATOR_CONFIG" ${genesis[@]+"${genesis[@]}"} | tee "$RUN_DIR/provision-$slot.log"
    session="$(sed -n 's/^ *session_id: *//p' "$RUN_DIR/provision-$slot.log" | head -1)"
    [[ -n "$session" ]] || die "operator provision printed no session id."
    wait_heartbeat "$session"
    note "key provisioners may run their step now"
    ;;

  wait-kps)
    slot="${1:-$(active_slot)}"
    init_build
    open_slot_tunnel "$slot"
    note "waiting for the enclave to reconstruct the key (each KP submits through the relay)"
    for attempt in $(seq 1 120); do
      if key="$(fetch_field "$(slot_endpoint "$slot")" enclave-btc-pubkey)" && [[ -n "$key" ]]; then
        note "slot $slot holds $key"
        exit 0
      fi
      if ((attempt % 6 == 0)); then
        note "not yet [$attempt/120]"
      fi
      sleep 30
    done
    die "Slot $slot never reconstructed the key."
    ;;

  activate)
    slot="${1:-$(active_slot)}"
    init_build
    open_slot_tunnel "$slot"
    config="$RUN_DIR/operator-withdraw-$slot.yaml"
    [[ -f "$config" ]] || die "No config at $config; run provision for slot $slot first."
    note "activation waits out the heartbeat fence, about ten minutes"
    "$INIT_BIN" operator activate --config "$config"
    ;;

  verify)
    init_build
    for field in lifecycle enclave-btc-pubkey; do
      printf '   %-20s %s\n' "$field" "$(fetch_field "$RELAY" "$field")"
    done
    run_or_die "The public endpoint did not answer /info." \
      curl -fsS "$RELAY/info" -o "$RUN_DIR/info.json"
    jq -r '"   limiter \(.limiter != null)  committeeEpoch \(.committeeEpoch)  btcPubkey \(.btcPubkey)"' \
      "$RUN_DIR/info.json"
    ;;

  arm)
    slot="$(standby_slot)"
    assert_urn_exists "$(slot_urn "$slot")" 2> /dev/null || note "slot $slot does not exist yet"
    assert_plan '^\+ 1 to create$' '^\+ 1 to create$' --target "$(slot_urn "$slot")" --target-dependents
    confirm "Create the standby guardian on slot $slot?"
    pulumi_up_slot "$slot"
    wait_host_bootstrap "$(slot_instance "$slot")"
    ;;

  switchover)
    active="$(active_slot)"
    standby="$(other_slot "$active")"
    init_build
    open_slot_tunnel "$standby"
    armed="$(fetch_field "$(slot_endpoint "$standby")" enclave-btc-pubkey)"
    serving="$(fetch_field "$RELAY" enclave-btc-pubkey)"
    [[ -n "$armed" && "$armed" == "$serving" ]] \
      || die "The standby holds $armed but the serving guardian holds $serving; refusing to switch over."
    close_tunnels
    warn "After the old guardian stops there is no rollback."
    confirm "Promote slot $standby and stop slot $active?"
    enclave_cfg_set active-slot "$standby"
    assert_plan '' '^$' --target "$(slot_urn "$standby")" --target-dependents
    pulumi_up_slot "$standby"
    pulumi_up_proxy
    run_or_die "Could not stop the guardian on slot $active." \
      ssm_run "$(slot_instance "$active")" \
      'systemctl disable --now hashi-guardian-enclave.service hashi-guardian-bridge.service'
    note "slot $active stopped; activate slot $standby next"
    ;;

  teardown)
    slot="$(standby_slot)"
    enclave_cfg_set "slot-$slot-enabled" false
    assert_plan '^- 1 to delete$' '^- 1 to delete$' --target "$(slot_urn "$slot")" --target-dependents
    confirm "Destroy the retired slot $slot?"
    pulumi_up_slot "$slot"
    ;;

  rotate-kp-set)
    action="${1:-}"
    init_build
    slot="$(standby_slot)"
    case "$action" in
      init)
        open_slot_tunnel "$slot"
        operator_config rotate-signer "$slot"
        "$INIT_BIN" operator rotate-kp-set init --config "$OPERATOR_CONFIG"
        ;;
      submit)
        submissions_dir="${2:-}"
        [[ -d "$submissions_dir" ]] \
          || die "Usage: $0 $ENV_NAME rotate-kp-set submit <submissions-dir> (from download-kp-submissions.sh)"
        flags=()
        for submission in "$submissions_dir"/*.rotation; do
          [[ -f "$submission" ]] || die "No .rotation files in $submissions_dir."
          flags+=(--submission "$submission")
        done
        open_slot_tunnel "$slot"
        config="$RUN_DIR/operator-rotate-signer.yaml"
        [[ -f "$config" ]] || die "No config at $config; run rotate-kp-set init first."
        note "submitting ${#flags[@]} signatures, then waiting for every new key provisioner"
        "$INIT_BIN" operator rotate-kp-set submit --config "$config" "${flags[@]}"
        ;;
      result)
        note "the new set is dealt; point KP_ROSTER_DIR at the new roster in .hashi/guardian.env"
        ;;
      *) die "Usage: $0 $ENV_NAME rotate-kp-set <init|submit|result>" ;;
    esac
    ;;

  *) die "Unknown step: $STEP. Run $0 --help for the list." ;;
esac
