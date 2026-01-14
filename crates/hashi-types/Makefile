.PHONY: proto
proto: ## Build proto files
	cargo run -p proto-build

.PHONY: buf-lint
buf-lint: ## Run buf lint
	buf lint

.PHONY: buf-fmt
buf-fmt: ## buf format code
	buf format -w

.PHONY: check-breaking
check-breaking: ## Run buf breaking
	# buf breaking --against 'https://github.com/MystenLabs/sui-apis.git#branch=main'

%:
	$(MAKE) -C ../.. $@
