
GO_SRC := $(shell find -type f -name '*.go' ! -path '*/vendor/*')
VERSION ?= $(shell git describe --dirty)

all: vet test makecerts

makecerts:
	CGO_ENABLED=0 go build -a -ldflags "-extldflags '-static' -X main.Version=$(VERSION)" -o makecerts .

vet:
	go vet

# Check code conforms to go fmt
style:
	! gofmt -s -l $(GO_SRC) 2>&1 | read 2>/dev/null

# Format the code
fmt:
	gofmt -s -w $(GO_SRC)

test:
	go test -v -covermode count -coverprofile=cover.test.out
	
.PHONY: test vet
