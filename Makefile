# RiftRoute — developer Makefile.
# The daemon + CLI are cgo-free (pure-Go SQLite); only the Wails GUI needs cgo
# and a per-OS toolchain (AGENTS §8). See README for prerequisites.

VERSION ?= 0.0.1-dev
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
WAILS   := $(shell go env GOPATH)/bin/wails
CORE_PKGS := ./internal/... ./cmd/...

.PHONY: all build daemon cli desktop dev test vet fmt tidy cross clean run-daemon bindings

all: build

## build: build the daemon and CLI into ./bin
build: daemon cli

daemon:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/riftrouted ./cmd/riftrouted

cli:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/riftroute ./cmd/riftroute

## desktop: build the native GUI app (RiftRoute.app / binary) via Wails
desktop:
	cd desktop && $(WAILS) build -trimpath -ldflags "-X main.version=$(VERSION)"

## dev: run the GUI with hot reload (rebuilds + restarts on change)
dev:
	cd desktop && $(WAILS) dev -ldflags "-X main.version=$(VERSION)"

## bindings: regenerate the typed Wails TS bindings from bound Go methods
bindings:
	cd desktop && $(WAILS) generate module

## test: run unit/integration tests for the daemon, CLI, and engine (not the GUI)
test:
	go test $(CORE_PKGS)

vet:
	go vet $(CORE_PKGS)

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

## cross: prove every config compiles — linux (cgo off) + windows fallback (AGENTS §8)
cross:
	GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -o /dev/null ./cmd/...
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -o /dev/null ./cmd/...
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -o /dev/null ./cmd/...
	@echo "all target configurations compile"

## run-daemon: run the daemon locally on a dev socket with the fake provider
run-daemon: daemon
	./bin/riftrouted -socket /tmp/riftroute-dev.sock -db /tmp/riftroute-dev.db -provider fake -log debug

clean:
	rm -rf bin desktop/build/bin desktop/frontend/dist/assets
