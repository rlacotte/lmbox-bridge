# LMbox Bridge — build + test targets.
#
# Run `make help` for the catalog.

BINARY        := lmbox-bridge
ENROLL_BINARY := lmbox-bridge-enroll
PKG           := ./cmd/lmbox-bridge
ENROLL_PKG    := ./cmd/lmbox-bridge-enroll
VERSION       := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
              -X main.Version=$(VERSION) \
              -X main.Commit=$(COMMIT) \
              -X main.BuildDate=$(BUILD_DATE)

.PHONY: help
help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build both binaries into ./bin
	@mkdir -p bin
	go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY) $(PKG)
	go build -ldflags '$(LDFLAGS)' -o bin/$(ENROLL_BINARY) $(ENROLL_PKG)

.PHONY: build-linux
build-linux: ## Cross-compile both binaries for Linux amd64
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	  go build -ldflags '$(LDFLAGS)' -o bin/$(ENROLL_BINARY)-linux-amd64 $(ENROLL_PKG)

.PHONY: build-linux-arm64
build-linux-arm64: ## Cross-compile both binaries for Linux arm64
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	  go build -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-linux-arm64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
	  go build -ldflags '$(LDFLAGS)' -o bin/$(ENROLL_BINARY)-linux-arm64 $(ENROLL_PKG)

.PHONY: test
test: ## Run all unit + E2E tests
	go test -race ./...

.PHONY: test-short
test-short: ## Run unit tests only, no race (faster, for iteration)
	go test -short ./...

.PHONY: cover
cover: ## Run tests with coverage profile
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run staticcheck if installed, otherwise vet
	@if command -v staticcheck >/dev/null 2>&1; then \
	  staticcheck ./...; \
	else \
	  echo "staticcheck not installed, falling back to vet"; \
	  go vet ./...; \
	fi

.PHONY: docker
docker: ## Build the OCI image
	docker build -t lmbox-bridge:$(VERSION) \
	  --build-arg VERSION=$(VERSION) \
	  --build-arg COMMIT=$(COMMIT) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  -f deploy/docker/Dockerfile .

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin coverage.out

.PHONY: ci
ci: vet test build-linux ## What CI runs (vet → test → linux build)

.DEFAULT_GOAL := help
