# Set the default target of this Makefile
.PHONY: all
all:: ci ## Default target, runs the CI process

# Set parallel build jobs if not already set
CARGO_BUILD_JOBS ?= $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

.PHONY: check-fmt
check-fmt: ## Check code formatting
	cargo fmt -- --config imports_granularity=Item --config format_code_in_doc_comments=true --check
	buf format --diff --exit-code

.PHONY: fmt
fmt: ## Format code
	cargo fmt -- --config imports_granularity=Item --config format_code_in_doc_comments=true
	$(MAKE) -C crates/hashi buf-fmt

.PHONY: buf-lint
buf-lint: ## Run buf lint
	$(MAKE) -C crates/hashi buf-lint

.PHONY: test
test: ## Run all tests
	CARGO_BUILD_JOBS=$(CARGO_BUILD_JOBS) cargo nextest run --all-features
	CARGO_BUILD_JOBS=$(CARGO_BUILD_JOBS) cargo test --all-features --doc

.PHONY: proto
proto: ## Build proto files
	$(MAKE) -C crates/hashi proto

.PHONY: clippy
clippy: ## run cargo clippy
	CARGO_BUILD_JOBS=$(CARGO_BUILD_JOBS) cargo clippy --all-features --all-targets

.PHONY: doc
doc: ## Generate documentation
	CARGO_BUILD_JOBS=$(CARGO_BUILD_JOBS) RUSTDOCFLAGS="-Dwarnings --cfg=doc_cfg -Zunstable-options --generate-link-to-definition" RUSTC_BOOTSTRAP=1 cargo doc --all-features --no-deps

.PHONY: doc-open
doc-open: ## Generate and open documentation
	CARGO_BUILD_JOBS=$(CARGO_BUILD_JOBS) RUSTDOCFLAGS="--cfg=doc_cfg -Zunstable-options --generate-link-to-definition" RUSTC_BOOTSTRAP=1 cargo doc --all-features --no-deps --open

.PHONY: ci
ci: check-fmt buf-lint clippy test ## Run the full CI process

.PHONY: is-dirty
is-dirty: ## Checks if repository is dirty
	@(test -z "$$(git diff)" || (git diff && false)) && (test -z "$$(git status --porcelain)" || (git status --porcelain && false))

.PHONY: clean
clean: ## Clean build artifacts
	cargo clean

.PHONY: clean-all
clean-all: clean ## Clean all generated files, including those ignored by Git. Force removal.
	git clean -dXf

.PHONY: help
help: ## Show this help
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
