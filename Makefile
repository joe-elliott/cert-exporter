GOPATH := $(shell go env GOPATH)

all: build

$(GOPATH)/bin/goreleaser:
	curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | BINDIR=$(GOPATH)/bin sh

build: $(GOPATH)/bin/goreleaser
	$(GOPATH)/bin/goreleaser build --skip-validate --rm-dist

snapshot: $(GOPATH)/bin/goreleaser
	$(GOPATH)/bin/goreleaser --snapshot --skip-publish --rm-dist

release: $(GOPATH)/bin/goreleaser
	$(GOPATH)/bin/goreleaser release

clean:
	rm -rf dist

.PHONY: all build snapshot release clean
