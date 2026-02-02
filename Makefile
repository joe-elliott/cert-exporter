GOPATH := $(shell go env GOPATH)
GORELEASER := $(GOPATH)/bin/goreleaser

all: build

$(GORELEASER):
	go install github.com/goreleaser/goreleaser@v1.9.2

build: $(GORELEASER)
	$(GORELEASER) build --skip-validate --rm-dist

test:
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...

test-integration:
	go test -v -tags=integration ./integration_test.go

test-all: test test-integration

release-snapshot: $(GORELEASER)
	$(GORELEASER) release --snapshot --skip-publish --rm-dist

release: $(GORELEASER)
	$(GORELEASER) release --rm-dist

clean:
	rm -rf dist
	rm -f coverage.txt

.PHONY: all build test test-integration test-all release-snapshot release clean
