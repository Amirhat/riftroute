# RiftRoute — developer Makefile.
# The daemon + CLI are cgo-free (pure-Go SQLite); only the Wails GUI needs cgo
# and a per-OS toolchain (AGENTS §8). See README for prerequisites.

# Releases pass VERSION explicitly (CI: the tag). Local builds are labelled from
# git — e.g. 0.2.3-4-ga5e49c2-dirty — so a dev daemon never claims to be a
# release. The commit/commit-time/dirty flag are also embedded by the Go
# toolchain and reported by `riftroute version`.
ifeq ($(origin VERSION), undefined)
VERSION := $(or $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//'),0.0.0-dev)
endif
LDFLAGS := -s -w -X main.version=$(VERSION)
# Wails builds the GUI without the toolchain's VCS stamp; pass the commit in
# explicitly so the app can tell which build it is (and whether the daemon
# it talks to is older or newer). The Go toolchain stamps daemon/CLI itself.
BI := github.com/Amirhat/riftroute/internal/buildinfo
COMMIT      := $(shell git rev-parse HEAD 2>/dev/null)
COMMIT_TIME := $(shell TZ=UTC0 git log -1 --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd 2>/dev/null)
MODIFIED    := $(if $(shell git status --porcelain 2>/dev/null),true,false)
BUILDINFO_LDFLAGS := -X $(BI).linkCommit=$(COMMIT) -X $(BI).linkCommitTime=$(COMMIT_TIME) -X $(BI).linkModified=$(MODIFIED)
GOFLAGS := -trimpath
WAILS   := $(shell go env GOPATH)/bin/wails
CORE_PKGS := ./internal/... ./cmd/...

.PHONY: all build daemon cli desktop desktop-universal dev test test-e2e test-tunnels-linux vet fmt tidy cross clean run-daemon bindings \
        dist dist-binaries checksums package-deb package-dmg package-appimage tray openvpn strongswan

all: build

## build: build the daemon and CLI into ./bin
build: daemon cli

daemon:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/riftrouted ./cmd/riftrouted

cli:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/riftroute ./cmd/riftroute

## desktop: build the native GUI app (RiftRoute.app / binary) via Wails
desktop:
	cd desktop && $(WAILS) build -trimpath -ldflags "-X main.version=$(VERSION) $(BUILDINFO_LDFLAGS)"

## desktop-universal: build the macOS GUI as a universal (arm64 + x86_64) app so
## it runs on every Mac — Apple Silicon and Intel. Used by the release DMG.
desktop-universal:
	cd desktop && $(WAILS) build -platform darwin/universal -trimpath -ldflags "-X main.version=$(VERSION) $(BUILDINFO_LDFLAGS)"

## tray: build the menu-bar/system-tray companion (cgo + native tray libs).
## Linux also needs libayatana-appindicator3-dev (or libappindicator3-dev).
tray:
	CGO_ENABLED=1 go build $(GOFLAGS) -tags tray -ldflags "$(LDFLAGS)" -o bin/riftroute-tray ./cmd/riftroute-tray

## dev: run the GUI with hot reload (rebuilds + restarts on change)
dev:
	cd desktop && $(WAILS) dev -ldflags "-X main.version=$(VERSION) $(BUILDINFO_LDFLAGS)"

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

## test-tunnels-linux: real Linux check of OpenVPN tunnels in Docker — the
## Linux daemon, a router, and an old-style OpenVPN server (needs Docker)
test-tunnels-linux:
	test/tunnels-linux/run.sh

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

## openvpn: build the openvpn that ships on macOS (macOS host; scripts/build-openvpn.sh)
openvpn:
	scripts/build-openvpn.sh arm64 $(OPENVPN_DIR)/arm64
	scripts/build-openvpn.sh x86_64 $(OPENVPN_DIR)/x86_64
	scripts/build-openvpn.sh universal $(OPENVPN_DIR)/universal

# The openvpn the darwin tarballs ship next to riftrouted, per architecture:
# $(OPENVPN_DIR)/<arm64|x86_64>/openvpn and licenses/ (`make openvpn`, or the
# release workflow's openvpn job). Without it the tarballs still build — and
# tunnels on macOS then say they need a release that includes it; never
# Homebrew's. REQUIRE_OPENVPN=1 makes a missing one an error.
OPENVPN_DIR ?= build/openvpn

## strongswan: build the charon-cmd that ships on macOS for IKEv2 (macOS host; scripts/build-strongswan.sh)
strongswan:
	scripts/build-strongswan.sh arm64 $(STRONGSWAN_DIR)/arm64
	scripts/build-strongswan.sh x86_64 $(STRONGSWAN_DIR)/x86_64
	scripts/build-strongswan.sh universal $(STRONGSWAN_DIR)/universal

# The same for strongSwan's charon-cmd (IKEv2 tunnels): $(STRONGSWAN_DIR)/
# <arch>/charon-cmd and licenses/, which go in the tarball as charon-cmd and
# licenses/charon-cmd/. REQUIRE_STRONGSWAN=1 makes a missing one an error.
STRONGSWAN_DIR ?= build/strongswan

## dist-binaries: cross-compile CLI+daemon tarballs for all release targets
dist-binaries:
	@mkdir -p dist
	@set -e; for t in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64; do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "→ $$os/$$arch"; \
		d=$$(mktemp -d); \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$d/riftrouted ./cmd/riftrouted; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $$d/riftroute  ./cmd/riftroute; \
		files="riftroute riftrouted"; \
		if [ $$os = darwin ]; then \
			ov=$(OPENVPN_DIR)/$$( [ $$arch = amd64 ] && echo x86_64 || echo $$arch ); \
			if [ -f $$ov/openvpn ] && [ -d $$ov/licenses ]; then \
				cp $$ov/openvpn $$d/openvpn; chmod 755 $$d/openvpn; cp -R $$ov/licenses $$d/licenses; \
				files="$$files openvpn licenses"; echo "  + openvpn from $$ov"; \
			elif [ -n "$(REQUIRE_OPENVPN)" ]; then \
				echo "missing $$ov/openvpn (+ licenses/) — build it with scripts/build-openvpn.sh" >&2; exit 1; \
			else \
				echo "  (no $$ov/openvpn: this tarball ships without openvpn; tunnels won't be available on macOS)"; \
			fi; \
			ss=$(STRONGSWAN_DIR)/$$( [ $$arch = amd64 ] && echo x86_64 || echo $$arch ); \
			if [ -f $$ss/charon-cmd ] && [ -d $$ss/licenses ]; then \
				cp $$ss/charon-cmd $$d/charon-cmd; chmod 755 $$d/charon-cmd; \
				mkdir -p $$d/licenses; cp -R $$ss/licenses $$d/licenses/charon-cmd; \
				files="$$files charon-cmd"; case " $$files " in *" licenses "*) ;; *) files="$$files licenses";; esac; \
				echo "  + charon-cmd from $$ss"; \
			elif [ -n "$(REQUIRE_STRONGSWAN)" ]; then \
				echo "missing $$ss/charon-cmd (+ licenses/) — build it with scripts/build-strongswan.sh" >&2; exit 1; \
			else \
				echo "  (no $$ss/charon-cmd: this tarball ships without it; IKEv2 tunnels won't be available on macOS)"; \
			fi; \
		fi; \
		tar -C $$d -czf dist/riftroute_$(VERSION)_$${os}_$${arch}.tar.gz $$files; \
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
