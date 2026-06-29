<!-- Thanks for contributing! Keep PRs to one logical change. -->

## What & why

<!-- What does this change do, and why? Link any related issue (Fixes #123). -->

## How it was tested

<!-- Commands you ran; new tests added. -->

- [ ] `make test` (Go unit/integration) passes
- [ ] `make test-e2e` (daemon ↔ socket ↔ client ↔ CLI) passes
- [ ] `go test -race ./internal/... ./cmd/...` is clean
- [ ] `make cross` compiles all targets (cgo-free)
- [ ] Frontend: `cd desktop/frontend && npm test` passes (if GUI touched)
- [ ] Linux netns suite updated/passing (if route/firewall mutation touched)

## Safety checklist

- [ ] No live-host mutation: route/firewall/DNS changes verified on `-provider fake` and/or netns only
- [ ] Route changes go through the Apply Protocol and stay ownership-scoped
- [ ] `gofmt -s` + `go vet` clean; no `window.confirm/alert/prompt` added in the GUI
- [ ] Docs/CHANGELOG updated if behavior or usage changed
