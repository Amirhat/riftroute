# RiftRoute — developer Makefile.
# The daemon + CLI are cgo-free (pure-Go SQLite); only the Wails GUI needs cgo
# and a per-OS toolchain (AGENTS §8). See README for prerequisites.

VERSION ?= 0.0.1-dev
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath
WAILS   := $(shell go env GOPATH)/bin/wails
CORE_PKGS := ./internal/... ./cmd/...

.PHONY: all build daemon cli desktop desktop-universal dev test test-e2e vet fmt tidy cross clean run-daemon bindings \
        dist dist-binaries checksums package-deb package-dmg package-appimage tray

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

## desktop-universal: build the macOS GUI as a universal (arm64 + x86_64) app so
## it runs on every Mac — Apple Silicon and Intel. Used by the release DMG.
desktop-universal:
	cd desktop && $(WAILS) build -platform darwin/universal -trimpath -ldflags "-X main.version=$(VERSION)"

## tray: build the menu-bar/system-tray companion (cgo + native tray libs).
## Linux also needs libayatana-appindicator3-dev (or libappindicator3-dev).
tray:
	CGO_ENABLED=1 go build $(GOFLAGS) -tags tray -ldflags "$(LDFLAGS)" -o bin/riftroute-tray ./cmd/riftroute-tray

## dev: run the GUI with hot reload (rebuilds + restarts on change)
dev:
	cd desktop && $(WAILS) dev -ldflags "-X main.version=$(VERSION)"

## bindings: regenerate the typed Wails TS bindings from bound Go methods
bindings:
	cd desktop && $(WAILS) generate module

## test: run unit/integration tests for the daemon, CLI, and engine (not the GUI)
test:
	go test $(CORE_PKGS)

## test-e2e: real end-to-end — builds the binaries, drives the daemon over a
## live socket through the full apply/confirm/rollback/panic lifecycle (fake
## provider; host-safe, offline).
test-e2e:
	go test -count=1 ./test/e2e/...

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

## dist-binaries: cross-compile CLI+daemon tarballs for all release targets
dist-binaries:
	@mkdir -p dist
	@for t in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "→ $$os/$$arch"; \
		d=$$(mktemp -d); \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$d/riftrouted ./cmd/riftrouted; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$d/riftroute  ./cmd/riftroute; \
		tar -C $$d -czf dist/riftroute_$(VERSION)_$${os}_$${arch}.tar.gz riftroute riftrouted; \
		rm -rf $$d; \
	done
	@echo "binaries in dist/"

## checksums: write a sha256sum manifest over everything in dist/
checksums:
	@cd dist && shasum -a 256 * > checksums.txt 2>/dev/null || (cd dist && sha256sum * > checksums.txt)
	@echo "wrote dist/checksums.txt"

## package-deb: build a .deb (Linux) — VERSION/ARCH override defaults
package-deb:
	VERSION=$(VERSION) packaging/deb/build-deb.sh

## package-dmg: package the built RiftRoute.app into a .dmg (macOS)
package-dmg: desktop
	VERSION=$(VERSION) packaging/macos/build-dmg.sh

## package-appimage: build a portable AppImage of the GUI (Linux)
package-appimage: desktop
	VERSION=$(VERSION) packaging/appimage/build-appimage.sh

## dist: cross binaries + checksums (the always-buildable release core)
dist: dist-binaries checksums

clean:
	rm -rf bin dist desktop/build/bin desktop/frontend/dist/assets
