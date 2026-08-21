REGISTRY := local
BUCKET_NAME ?= guardian-test-bucket
AWS_REGION ?= us-east-1
GIT_REVISION ?= $(shell git -C ../.. describe --always --exclude '*' --dirty --abbrev=8)
# Extra cargo features; empty = the real enclave build (see Containerfile).
FEATURES ?=
# Enclave boot mode; empty = withdraw, "true" = ceremony (see Containerfile).
CEREMONY_MODE ?=

.DEFAULT_GOAL :=
.PHONY: default
default: out/nitro.eif

out:
	mkdir -p out

out/nitro.eif: $(shell git ls-files ../../Cargo.toml ../../Cargo.lock ../../crates/hashi-guardian ../../crates/hashi-types .) | out
	docker build \
		--pull \
		--tag $(REGISTRY)/guardian-enclave \
		--progress=plain \
		--platform linux/amd64 \
		--provenance=false \
		--output type=local,rewrite-timestamp=true,dest=out \
		--build-arg BUCKET_NAME=$(BUCKET_NAME) \
		--build-arg AWS_REGION=$(AWS_REGION) \
		--build-arg GIT_REVISION=$(GIT_REVISION) \
		--build-arg FEATURES=$(FEATURES) \
		--build-arg CEREMONY_MODE=$(CEREMONY_MODE) \
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

# Reproduce the resolution + root-lock subset assertion the EIF build performs,
# in the EIF build's own toolchain, without building the EIF. CI runs this per
# PR and per merge (guardian-enclave-resolve).
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
