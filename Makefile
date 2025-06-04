CGO_ENABLED ?= 1
GOFLAGS ?= "-buildmode=exe"
GO := CGO_ENABLED=$(CGO_ENABLED) GOFLAGS="$(GOFLAGS)" go

GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)

GO_TAGS := -tags=

BIN := lighthouse_$(GOOS)_$(GOARCH)

LDFLAGS := ""

.PHONY: all
all: build test library-test

.PHONY: generate
generate:
	$(GO) generate

.PHONY: build
build: go-build

.PHONY: test
test: go-test library-test

.PHONY: go-build
go-build: generate
	$(GO) build $(GO_TAGS) -o $(BIN) -ldflags $(LDFLAGS)

.PHONY: go-test
go-test: generate
	$(GO) test $(GO_TAGS) ./...

library-test:
	$(GO) run github.com/open-policy-agent/opa test --v0-compatible libraries/envoy-v2.0
	$(GO) run github.com/open-policy-agent/opa test --v0-compatible libraries/envoy-v2.1
	$(GO) run github.com/open-policy-agent/opa test --v0-compatible libraries/kong-gateway-v1
	$(GO) run github.com/open-policy-agent/opa test --v0-compatible libraries/kubernetes-v2
	$(GO) run github.com/open-policy-agent/opa test --v0-compatible libraries/match-v1
	$(GO) run github.com/open-policy-agent/opa test --v0-compatible libraries/terraform-v2.0

.PHONY: clean
clean:
	rm -f lighthouse_*_*
