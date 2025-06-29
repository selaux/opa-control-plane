CGO_ENABLED ?= 1
GOFLAGS ?= "-buildmode=exe"
GO := CGO_ENABLED=$(CGO_ENABLED) GOFLAGS="$(GOFLAGS)" go

GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)

GO_TAGS := -tags=

BIN := lighthouse_$(GOOS)_$(GOARCH)

LDFLAGS := ""

.PHONY: all
all: build test

.PHONY: generate
generate:
	$(GO) generate

.PHONY: build
build: go-build

.PHONY: test
test: go-test go-bench library-test authz-test

.PHONY: go-build
go-build: generate
	$(GO) build $(GO_TAGS) -o $(BIN) -ldflags $(LDFLAGS)

.PHONY: go-test
go-test: generate
	$(GO) test -timeout=5s $(GO_TAGS) ./...

.PHONY: go-bench
go-bench: generate
	$(GO) test -benchmem -run=- -bench=. $(GO_TAGS) ./...

.PHONY: go-e2e-migrate-test
go-e2e-migrate-test: generate
	$(GO) test -tags=migration_e2e ./e2e -v -run '^TestMigration/'

.PHONY: libary-test
library-test:
	make -C libraries/entitlements-v1 test
	make -C libraries/envoy-v2.0 test
	make -C libraries/envoy-v2.1 test
	make -C libraries/kong-gateway-v1 test
	make -C libraries/kubernetes-v2 test
	make -C libraries/terraform-v2.0 test

.PHONY: authz-test
authz-test:
	$(GO) run github.com/open-policy-agent/opa test -b ./internal/authz

.PHONY: clean
clean:
	rm -f lighthouse_*_*
