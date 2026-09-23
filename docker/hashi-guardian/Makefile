REGISTRY := local
# Extra cargo features; empty = the real enclave build (see Containerfile).
FEATURES ?=

.DEFAULT_GOAL :=
.PHONY: default
default: out/nitro.eif

out:
	mkdir -p out

# Build-context inputs. .github/workflows/guardian-enclave.yml builds main pushes
# that touch this list; a path added here must be added there too.
out/nitro.eif: $(shell git ls-files ../../Cargo.toml ../../Cargo.lock ../../.dockerignore ../../crates .) | out
	docker build \
		--pull \
		--tag $(REGISTRY)/guardian-enclave \
		--progress=plain \
		--platform linux/amd64 \
		--provenance=false \
		--output type=local,rewrite-timestamp=true,dest=out \
		--build-arg FEATURES=$(FEATURES) \
		-f Containerfile \
		../..

.PHONY: run
run: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 512M \
		--eif-path out/nitro.eif

.PHONY: run-debug
run-debug: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 512M \
		--eif-path out/nitro.eif \
		--debug-mode \
		--attach-console

# Resolve dependencies in the enclave toolchain without compiling the EIF.
.PHONY: resolve-check
resolve-check:
	docker build \
		--pull \
		--progress=plain \
		--platform linux/amd64 \
		--target resolve \
		-f Containerfile \
		../..

.PHONY: clean
clean:
	rm -rf out/
