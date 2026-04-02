REGISTRY := local
BUCKET_NAME ?= guardian-test-bucket
AWS_REGION ?= us-east-1

.DEFAULT_GOAL :=
.PHONY: default
default: out/nitro.eif

out:
	mkdir -p out

out/nitro.eif: $(shell git ls-files ../../crates/hashi-guardian ../../crates/hashi-types) | out
	docker build \
		--pull \
		--tag $(REGISTRY)/guardian-enclave \
		--progress=plain \
		--platform linux/amd64 \
		--provenance=false \
		--output type=local,rewrite-timestamp=true,dest=out \
		--build-arg BUCKET_NAME=$(BUCKET_NAME) \
		--build-arg AWS_REGION=$(AWS_REGION) \
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

.PHONY: clean
clean:
	rm -rf out/
