GO				?= go
GOPATH			?= $$($(GO) env GOPATH)
BINDIR          ?= $(CURDIR)/bin

codegen:
	GO111MODULE=on $(GO) get github.com/golang/mock/mockgen@v1.4.3 google.golang.org/protobuf/cmd/protoc-gen-go
	PATH=$$PATH:$(GOPATH)/bin $(GO) generate ./...

	# Make sure the IPFIX registries are up-to-date.
    # Hitting 304 error when getting IANA registry csv file multiple times, so
    # skipping this check temporarily.
	# GO111MODULE=on $(GO) run pkg/registry/build_registry/build_registry.go

    # Generate protobuf code for flow.proto with protoc.
	protoc --go_out=. --plugin=$(GOPATH)/bin/protoc-gen-go pkg/producer/protobuf/*.proto

.coverage:
	mkdir -p ./.coverage

test-unit: .coverage
	$(GO) test -race ./... -covermode=atomic -coverprofile=.coverage/coverage_unit.txt

test-integration: .coverage
	$(GO) test -race ./pkg/test/... -tags=integration -covermode=atomic -coverprofile=.coverage/coverage_integration.txt -coverpkg github.com/vmware/go-ipfix/pkg/collector,github.com/vmware/go-ipfix/pkg/exporter,github.com/vmware/go-ipfix/pkg/intermediate,github.com/vmware/go-ipfix/pkg/producer

.golangci-bin:
	@echo "===> Installing Golangci-lint <==="
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $@ v1.32.1

golangci:.golangci-bin
	@GOOS=linux .golangci-bin/golangci-lint run -c .golangci.yml

collector:
	@mkdir -p $(BINDIR)
	GOOS=linux $(GO) build -o $(BINDIR) github.com/vmware/go-ipfix/cmd/collector/

### Docker images ###

docker-collector:
	@echo "===> Building antrea/ipfix-collector Docker image <==="
	docker build --pull -t antrea/ipfix-collector -f build/images/Dockerfile.build.collector .
