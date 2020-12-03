GO				?= go
GOPATH			?= $$($(GO) env GOPATH)
BINDIR          ?= $(CURDIR)/bin

codegen:
	GO111MODULE=on $(GO) get github.com/golang/mock/mockgen@v1.4.3
	PATH=$$PATH:$(GOPATH)/bin $(GO) generate ./...

	# Make sure the IPFIX registries are up-to-date.
    # Hitting 304 error when getting IANA registry csv file multiple times, so
    # skipping this check temporarily.
	#GO111MODULE=on $(GO) run pkg/registry/build_registry/build_registry.go

.coverage:
	mkdir -p ./.coverage

test-unit: .coverage
	$(GO) test -race ./... -covermode=atomic -coverprofile=.coverage/coverage_unit.txt

test-integration: .coverage
	$(GO) test -race ./pkg/test/... -tags=integration -covermode=atomic -coverprofile=.coverage/coverage_integration.txt -coverpkg github.com/vmware/go-ipfix/pkg/collector,github.com/vmware/go-ipfix/pkg/exporter,github.com/vmware/go-ipfix/pkg/intermediate

golangci:
	@curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.21.0
	$(GOPATH)/bin/golangci-lint run -c .golangci.yml

collector:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) github.com/vmware/go-ipfix/cmd/collector/

### Docker images ###

docker-collector:
	@echo "===> Building antrea/ipfix-collector Docker image <==="
	docker build --pull -t antrea/ipfix-collector -f build/images/Dockerfile.build.collector .
