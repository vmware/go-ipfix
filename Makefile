GO				?= go
GOPATH			?= $$($(GO) env GOPATH)

codegen:
	GO111MODULE=on $(GO) get github.com/golang/mock/mockgen@v1.4.3
	PATH=$$PATH:$(GOPATH)/bin $(GO) generate ./...

check:
	$(GO) test ./...