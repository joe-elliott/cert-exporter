GOPATH := $(shell go env GOPATH)
GORELEASER := $(GOPATH)/bin/goreleaser

all: build

$(GORELEASER):
	curl -sfL https://install.goreleaser.com/github.com/goreleaser/goreleaser.sh | BINDIR=$(GOPATH)/bin sh

build: $(GORELEASER)
	$(GORELEASER) build --skip-validate --rm-dist

release-snapshot: $(GORELEASER)
	$(GORELEASER) release --snapshot --skip-publish --rm-dist

release: $(GORELEASER)
	$(GORELEASER) release --rm-dist

clean:
	rm -rf dist

.PHONY: all build release-snapshot release clean
