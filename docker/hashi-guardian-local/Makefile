# Copyright (c), Mysten Labs, Inc.
# SPDX-License-Identifier: Apache-2.0

COMPOSE := docker compose

.DEFAULT_GOAL := help
.PHONY: help up bootstrap smoke get-info gen-master-key logs down

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

up: ## Build + start minio, host, enclave, proxy (no chain needed)
	$(COMPOSE) up -d --build minio bucket-init host enclave proxy

bootstrap: ## OperatorInit + ProvisionerInit (needs a devnet committee; see README)
	$(COMPOSE) run --rm bootstrap

smoke: ## End-to-end gRPC through the proxy -> host -> enclave -> guardian
	@echo "== gRPC health (proxy) =="
	$(COMPOSE) exec -T proxy socat -T2 OPEN:/dev/null TCP4:127.0.0.1:3000 && echo "proxy :3000 reachable"
	@echo "== GetGuardianInfo through the proxy (errors pre-bootstrap, but proves the full path) =="
	$(COMPOSE) exec -T proxy grpcurl -plaintext -import-path /proto \
		-proto sui/hashi/v1alpha/guardian_service.proto \
		localhost:3000 sui.hashi.v1alpha.GuardianService/GetGuardianInfo || true

get-info: ## GetGuardianInfo through the proxy (expects a bootstrapped guardian)
	$(COMPOSE) exec -T proxy grpcurl -plaintext -import-path /proto \
		-proto sui/hashi/v1alpha/guardian_service.proto \
		localhost:3000 sui.hashi.v1alpha.GuardianService/GetGuardianInfo

gen-master-key: ## Print a fresh HASHI_MASTER_SECRET_HEX / _PUBKEY_HEX pair
	$(COMPOSE) run --rm --no-deps --entrypoint /usr/bin/hashi-guardian-init bootstrap \
		tools generate-master-key --format env

logs: ## Tail logs
	$(COMPOSE) logs -f --tail=100

down: ## Stop everything and drop the MinIO volume
	$(COMPOSE) --profile bootstrap down -v
