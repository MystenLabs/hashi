# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

COMPOSE := docker compose
REPO_ROOT := $(shell cd ../.. && pwd)
# Where `hashi-localnet start` writes state.json (its default --data-dir).
LOCALNET_DIR ?= $(REPO_ROOT)/.hashi/localnet
STATE := $(LOCALNET_DIR)/state.json

.DEFAULT_GOAL := help
.PHONY: help up ceremony pubkey localnet-cmd provision smoke logs down \
	standby-up standby-provision switchover rotate

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Full local end-to-end (real ceremony + provision against a local sui node):"
	@echo "  1. make up          # MinIO + withdraw guardian + proxy"
	@echo "  2. make ceremony    # generate KP keys + run the ceremony -> BTC pubkey"
	@echo "  3. make localnet-cmd  # prints the 'hashi-localnet start ...' to run natively"
	@echo "  4. make provision   # operator provision + KP provision + activation"
	@echo "  5. make smoke       # GetGuardianInfo for the activated guardian"
	@echo ""
	@echo "Guardian rotation rehearsal (after the flow above; see README):"
	@echo "  make rotate         # standby-up + standby-provision + switchover"

# Extract the native localnet's connection details and run one provision.sh
# step inside the init container. $(1) = provision.sh args (mode + endpoint).
define run_provision
	@test -f "$(STATE)" || { echo "No localnet state at $(STATE). Run 'make localnet-cmd' and start it first."; exit 1; }
	@sui_rpc=$$(jq -r .sui_rpc_url "$(STATE)" | sed 's#127.0.0.1#host.docker.internal#; s#localhost#host.docker.internal#'); \
	pkg=$$(jq -r .package_id "$(STATE)"); obj=$$(jq -r .hashi_object_id "$(STATE)"); \
	echo "Provisioning against localnet: $$sui_rpc (pkg $$pkg)"; \
	SUI_RPC="$$sui_rpc" PACKAGE_ID="$$pkg" HASHI_OBJECT_ID="$$obj" \
	  $(COMPOSE) --profile init run --rm --build \
	    -e SUI_RPC -e PACKAGE_ID -e HASHI_OBJECT_ID \
	    init /scripts/provision.sh $(1)
endef

up: ## Build + start MinIO, host, withdraw enclave, proxy (no chain needed)
	@rm -f .env
	$(COMPOSE) up -d --build minio bucket-init host enclave proxy

ceremony: ## Generate KP keys + run the genesis ceremony (captures the BTC pubkey)
	$(COMPOSE) --profile ceremony up -d --build ceremony
	$(COMPOSE) --profile init run --rm --build init /scripts/ceremony.sh
	$(COMPOSE) --profile ceremony stop ceremony

pubkey: ## Print the ceremony BTC master pubkey (hex)
	@$(COMPOSE) --profile init run --rm -T --entrypoint cat init /work/guardian-btc-pubkey.hex; echo

localnet-cmd: ## Print the `hashi-localnet start` command wired to this guardian
	@pubkey=$$($(COMPOSE) --profile init run --rm -T --entrypoint cat init /work/guardian-btc-pubkey.hex 2>/dev/null); \
	if [ -z "$$pubkey" ]; then echo "Run 'make ceremony' first."; exit 1; fi; \
	echo "Run this NATIVELY (needs 'sui' + 'bitcoind' on PATH; publishes the guardian's"; \
	echo "ceremony pubkey + forms the committee; stays running):"; \
	echo ""; \
	echo "  cargo run -p e2e-tests --bin hashi-localnet -- start \\"; \
	echo "    --data-dir $(LOCALNET_DIR) \\"; \
	echo "    --guardian-url http://localhost:3000 \\"; \
	echo "    --guardian-btc-pubkey $$pubkey"

provision: ## operator provision + KP provision + activation (needs the native localnet running)
	$(call run_provision,full)

standby-up: ## Start the standby guardian pair and route the relay at it
	$(COMPOSE) --profile standby up -d --build --wait host-b enclave-b
	@printf 'ACTIVE_GUARDIAN_URL=http://host:3000\nSTANDBY_GUARDIAN_URL=http://host-b:3000\n' > .env
	$(COMPOSE) up -d proxy

standby-provision: ## Arm the standby via the relay: provision + KP shares, no activation
	$(call run_provision,arm http://host-b:3000)

switchover: ## Retire the active guardian and activate the armed standby
	@test -f .env || { echo "No rotation in flight. Run 'make standby-up' + 'make standby-provision' first."; exit 1; }
	@printf 'ACTIVE_GUARDIAN_URL=http://host-b:3000\nSTANDBY_GUARDIAN_URL=\n' > .env
	$(COMPOSE) up -d proxy
	$(COMPOSE) stop enclave host
	$(call run_provision,activate http://host-b:3000)
	$(MAKE) smoke

rotate: ## Full rotation rehearsal: standby-up + standby-provision + switchover
	$(MAKE) standby-up
	$(MAKE) standby-provision
	$(MAKE) switchover

smoke: ## GetGuardianInfo for the activated guardian through the proxy
	$(COMPOSE) exec -T proxy grpcurl -plaintext -import-path /proto \
		-proto sui/hashi/v1alpha/guardian_service.proto \
		localhost:3000 sui.hashi.v1alpha.GuardianService/GetGuardianInfo

logs: ## Tail logs
	$(COMPOSE) logs -f --tail=100

down: ## Stop everything and drop volumes
	$(COMPOSE) --profile ceremony --profile init --profile standby down -v
	rm -f .env
