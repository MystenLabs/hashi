# Set the default target of this Makefile
.PHONY: all
all:: ci ## Default target, runs the CI process

.PHONY: check-fmt
check-fmt: ## Check code formatting
	cargo fmt -- --config imports_granularity=Item --config format_code_in_doc_comments=true --check
	buf format --diff --exit-code

.PHONY: fmt
fmt: fmt-rust fmt-buf fmt-move ## Format all code (Rust, protobuf, and Move)

.PHONY: fmt-rust
fmt-rust: ## Format Rust code
	cargo fmt -- --config imports_granularity=Item --config format_code_in_doc_comments=true

.PHONY: fmt-buf
fmt-buf: ## Format protobuf files
	$(MAKE) -C crates/hashi-types buf-fmt

.PHONY: fmt-move
fmt-move: ## Format Move code
	prettier-move -w packages/*/sources/*.move
	prettier-move -w packages/*/sources/**/*.move
	prettier-move -w packages/*/tests/*.move
	prettier-move -w packages/*/tests/**/*.move

.PHONY: buf-lint
buf-lint: ## Run buf lint
	$(MAKE) -C crates/hashi-types buf-lint

.PHONY: test
test: ## Run all tests
	cargo nextest run --workspace --all-features
	cargo test --workspace --all-features --doc

.PHONY: test-move
test-move: ## Run all move tests
	ls -d packages/*/ | xargs -I {} bash -c "sui move test --path '{}'"

.PHONY: proto
proto: ## Build proto files
	$(MAKE) -C crates/hashi-types proto

.PHONY: clippy
clippy: ## run cargo clippy
	cargo clippy --workspace --all-features --all-targets

.PHONY: doc
doc: ## Generate documentation
	RUSTDOCFLAGS="-Dwarnings --cfg=doc_cfg -Zunstable-options --generate-link-to-definition" RUSTC_BOOTSTRAP=1 cargo doc --workspace --all-features --no-deps

.PHONY: doc-open
doc-open: ## Generate and open documentation
	RUSTDOCFLAGS="--cfg=doc_cfg -Zunstable-options --generate-link-to-definition" RUSTC_BOOTSTRAP=1 cargo doc --workspace --all-features --no-deps --open

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

.PHONY: book
book: ## Build and serve the design mdbook
	mdbook serve design
