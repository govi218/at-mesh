SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c
GIT_TAG := $(shell git describe --tags --exact-match 2>/dev/null)
GIT_COMMIT := $(shell git rev-parse --short=9 HEAD)
VERSION := $(if $(GIT_TAG),$(GIT_TAG),dev-$(GIT_COMMIT))

BUILD_DIR := dist

PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64

.PHONY: help
help: ## Print info about all commands
	@echo "Commands:"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[01;32m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the at-mesh binary
	go build -ldflags "-X main.Version=$(VERSION)" -o at-mesh ./cmd/at-mesh

.PHONY: run
run: ## Build and run at-mesh
	go build -ldflags "-X main.Version=dev-local" -o at-mesh ./cmd/at-mesh && ./at-mesh run

.PHONY: create-jwk
create-jwk: ## Create a JWK for signing OIDC tokens
	./at-mesh create-jwk --out keys/jwk.key

.PHONY: test
test: ## Run tests
	go clean -testcache && go test -v ./...

.PHONY: test-local
test-local: ## Run local smoke test (requires at-mesh running)
	./scripts/test-local.sh

.PHONY: lint
lint: ## Verify code style and run static checks
	go vet ./...
	test -z $(gofmt -l ./...)

.PHONY: fmt
fmt: ## Run syntax re-formatting
	go fmt ./...

.PHONY: check
check: ## Compile everything, checking syntax
	go build ./...

.PHONY: docker-build
docker-build: ## Build Docker image
	docker build -t at-mesh .

.PHONY: clean-dist
clean-dist: ## Remove all built binaries
	rm -rf $(BUILD_DIR)
