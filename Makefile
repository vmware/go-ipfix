GO              ?= go
GOPATH          ?= $$($(GO) env GOPATH)
BINDIR          ?= $(CURDIR)/bin
GOMOCK_VERSION         := v0.3.0
PROTOC_GEN_GO_VERSION  := v1.28.1
GOLANGCI_LINT_VERSION  := v1.60.3
GOLANGCI_LINT_BINDIR   := .golangci-bin
GOLANGCI_LINT_BIN      := $(GOLANGCI_LINT_BINDIR)/$(GOLANGCI_LINT_VERSION)/golangci-lint
GO_FILES               := $(shell find . -type d -name '.cache' -prune -o -type f -name '*.go' -print)

.PHONY: all
all: collector consumer

.mockgen-bin:
	GOBIN=$(CURDIR)/$@ $(GO) install go.uber.org/mock/mockgen@$(GOMOCK_VERSION)

.protoc-bin:
	GOBIN=$(CURDIR)/$@ $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)

.PHONY: codegen
codegen: .mockgen-bin .protoc-bin
	PATH=$(CURDIR)/.mockgen-bin:$$PATH $(GO) generate ./...

        # Make sure the IPFIX registries are up-to-date.
        # Hitting 304 error when getting IANA registry csv file multiple times, so
        # skipping this check temporarily.
        # GO111MODULE=on $(GO) run pkg/registry/build_registry/build_registry.go

        # Generate protobuf code for flow.proto with protoc.
	protoc --go_out=. --plugin=$(CURDIR)/.protoc-bin/protoc-gen-go pkg/kafka/producer/protobuf/*.proto

.coverage:
	mkdir -p ./.coverage

.PHONY: test-unit
test-unit: .coverage
	$(GO) test -race ./... -covermode=atomic -coverprofile=.coverage/coverage_unit.txt

.PHONY: test-integration
test-integration: .coverage
	$(GO) test -race ./pkg/test/... -tags=integration -covermode=atomic -coverprofile=.coverage/coverage_integration.txt -coverpkg github.com/vmware/go-ipfix/pkg/collector,github.com/vmware/go-ipfix/pkg/exporter,github.com/vmware/go-ipfix/pkg/intermediate,github.com/vmware/go-ipfix/pkg/kafka/producer

# code linting
$(GOLANGCI_LINT_BIN):
	@echo "===> Installing Golangci-lint <==="
	@rm -rf $(GOLANGCI_LINT_BINDIR)/* # delete old versions
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOLANGCI_LINT_BINDIR)/$(GOLANGCI_LINT_VERSION) $(GOLANGCI_LINT_VERSION)

.PHONY: golangci
golangci: $(GOLANGCI_LINT_BIN)
	@echo "===> Running golangci <==="
	@GOOS=linux $(GOLANGCI_LINT_BIN) run -c .golangci.yml

.PHONY: golangci-fix
golangci-fix: $(GOLANGCI_LINT_BIN)
	@echo "===> Running golangci-fix <==="
	@GOOS=linux $(GOLANGCI_LINT_BIN) run -c .golangci.yml --fix

.PHONY: collector
collector:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) github.com/vmware/go-ipfix/cmd/collector/

.PHONY: consumer
consumer:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) github.com/vmware/go-ipfix/cmd/consumer/

### Docker images ###

.PHONY: docker-collector
docker-collector:
	@echo "===> Building antrea/ipfix-collector Docker image <==="
	docker build --pull -t antrea/ipfix-collector -f build/images/Dockerfile.build.collector .

.PHONY: docker-consumer
docker-consumer:
	@echo "===> Building antrea/kafka-consumer Docker image <==="
	docker build --pull -t antrea/kafka-consumer -f build/images/Dockerfile.build.consumer .

.PHONY: manifest
manifest:
	@echo "===> Generating dev manifest for Go-ipfix <==="
	$(CURDIR)/hack/generate-manifest-collector.sh --mode dev > build/yamls/ipfix-collector.yaml

.PHONY: fmt
fmt:
	@echo
	@echo "===> Formatting Go files <==="
	@gofmt -s -l -w $(GO_FILES)

.PHONY: clean
clean:
	@rm -rf $(BINDIR)
	@rm -rf .mockgen-bin
	@rm -rf .protoc-bin
	@rm -rf $(GOLANGCI_LINT_BINDIR)
	@rm -rf .coverage
