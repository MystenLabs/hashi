# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

COMPOSE := docker compose
REPO_ROOT := $(shell cd ../.. && pwd)
# Where `hashi-localnet start` writes state.json (its default --data-dir).
LOCALNET_DIR ?= $(REPO_ROOT)/.hashi/localnet
STATE := $(LOCALNET_DIR)/state.json

.DEFAULT_GOAL := help
.PHONY: help up ceremony pubkey localnet-cmd provision smoke logs down

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Full local end-to-end (real ceremony + provision against a local sui node):"
	@echo "  1. make up          # MinIO + withdraw guardian + proxy"
	@echo "  2. make ceremony    # generate KP keys + run the ceremony -> BTC pubkey"
	@echo "  3. make localnet-cmd  # prints the 'hashi-localnet start ...' to run natively"
	@echo "  4. make provision   # operator provision + KP provision via the relay"
	@echo "  5. make smoke       # GetGuardianInfo through the proxy"

up: ## Build + start MinIO, host, withdraw enclave, proxy (no chain needed)
	$(COMPOSE) up -d --build minio bucket-init host enclave proxy

ceremony: ## Generate KP keys + run the genesis ceremony (captures the BTC pubkey)
	$(COMPOSE) --profile ceremony up -d --build ceremony
	$(COMPOSE) --profile init run --rm --build init /scripts/ceremony.sh
	$(COMPOSE) --profile ceremony stop ceremony
	@fps=$$($(COMPOSE) --profile init run --rm -T --entrypoint cat init /work/kp-fingerprints.csv); \
	echo "AUTHORIZED_KP_FINGERPRINTS=$$fps" > kp-roster.env; \
	echo "Handing the KP roster to the proxy relay: $$fps"; \
	$(COMPOSE) up -d proxy

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

provision: ## operator provision + KP provision (needs the native localnet running)
	@test -f "$(STATE)" || { echo "No localnet state at $(STATE). Run 'make localnet-cmd' and start it first."; exit 1; }
	@sui_rpc=$$(jq -r .sui_rpc_url "$(STATE)" | sed 's#127.0.0.1#host.docker.internal#; s#localhost#host.docker.internal#'); \
	pkg=$$(jq -r .package_id "$(STATE)"); obj=$$(jq -r .hashi_object_id "$(STATE)"); \
	echo "Provisioning against localnet: $$sui_rpc (pkg $$pkg)"; \
	SUI_RPC="$$sui_rpc" PACKAGE_ID="$$pkg" HASHI_OBJECT_ID="$$obj" \
	  $(COMPOSE) --profile init run --rm --build \
	    -e SUI_RPC -e PACKAGE_ID -e HASHI_OBJECT_ID \
	    init /scripts/provision.sh

smoke: ## GetGuardianInfo through the proxy -> host -> enclave -> guardian
	$(COMPOSE) exec -T proxy grpcurl -plaintext -import-path /proto \
		-proto sui/hashi/v1alpha/guardian_service.proto \
		localhost:3000 sui.hashi.v1alpha.GuardianService/GetGuardianInfo

logs: ## Tail logs
	$(COMPOSE) logs -f --tail=100

down: ## Stop everything and drop volumes
	$(COMPOSE) --profile ceremony --profile init down -v
	rm -f kp-roster.env
