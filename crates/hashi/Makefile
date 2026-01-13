.PHONY: buf-lint
buf-lint: ## Run buf lint
	buf lint

.PHONY: buf-fmt
buf-fmt: ## buf format code
	buf format -w

%:
	$(MAKE) -C ../.. $@
