BINARY := subconverter-ng
PKG := ./cmd/subconverter-ng
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test conformance vet run docker clean tidy

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

# Conformance renders the fixture subscriptions and asks the real clients
# (sing-box check, mihomo -t) whether they accept the output. Needs both
# binaries on PATH, or point CONFORMANCE_SINGBOX / CONFORMANCE_MIHOMO at them
# (CONFORMANCE_SINGBOX takes a comma-separated list for the version matrix).
conformance:
	@[ -n "$(CONFORMANCE_SINGBOX)" ] || command -v sing-box >/dev/null || { echo "conformance: no sing-box (install it or set CONFORMANCE_SINGBOX)"; exit 1; }
	@[ -n "$(CONFORMANCE_MIHOMO)" ] || command -v mihomo >/dev/null || { echo "conformance: no mihomo (install it or set CONFORMANCE_MIHOMO)"; exit 1; }
	CONFORMANCE_REQUIRE=1 go test -tags conformance ./internal/conformance -v

vet:
	go vet ./...

tidy:
	go mod tidy

run:
	go run $(PKG) serve --listen :25500

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) .

clean:
	rm -rf bin
