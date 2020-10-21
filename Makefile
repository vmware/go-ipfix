GO				?= go
GOPATH			?= $$($(GO) env GOPATH)

codegen:
	GO111MODULE=on $(GO) get github.com/golang/mock/mockgen@v1.4.3
	PATH=$$PATH:$(GOPATH)/bin $(GO) generate ./...

test-unit:
	$(GO) test ./... -covermode=atomic -coverprofile=coverage_unit.txt

test-integration:
	$(GO) test ./pkg/test/... -tags=integration -covermode=atomic -coverprofile=coverage_integration.txt -coverpkg github.com/vmware/go-ipfix/pkg/collector,github.com/vmware/go-ipfix/pkg/exporter

golangci:
	@curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.21.0
	$(GOPATH)/bin/golangci-lint run -c .golangci.yml
