GO                      ?= GO15VENDOREXPERIMENT=1 go
GOPATH                  := $(firstword $(subst :, ,$(shell $(GO) env GOPATH)))
GODEP                   ?= $(GOPATH)/bin/dep
GOLINTER                ?= $(GOPATH)/bin/gometalinter
pkgs                    = $(shell $(GO) list ./... | grep -v /vendor/)
TARGET                  ?= syncrepl_exporter

PREFIX                  ?= $(shell pwd)
BIN_DIR                 ?= $(shell pwd)

all: depcheck format vet gometalinter build test

test:
	@echo ">> running tests"
	@$(GO) test -short $(pkgs)

format:
	@echo ">> formatting code"
	@$(GO) fmt $(pkgs)

gometalinter: $(GOLINTER)
	@echo ">> linting code"
	@$(GOLINTER) --install > /dev/null
	@$(GOLINTER) --config=./.gometalinter.json ./...

build: depcheck
	@echo ">> building binaries"
	@CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"'

clean:
	@echo ">> Cleaning up"
	@$(RM) $(TARGET)

depcheck: $(GODEP)
	@echo ">> ensure vendoring"
	@$(GODEP) ensure

$(GOPATH)/bin/dep dep:
	@GOOS=$(shell uname -s | tr A-Z a-z) \
		GOARCH=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m))) \
		$(GO) get -u github.com/golang/dep/cmd/dep

$(GOPATH)/bin/gometalinter lint:
	@GOOS=$(shell uname -s | tr A-Z a-z) \
		GOARCH=$(subst x86_64,amd64,$(patsubst i%86,386,$(shell uname -m))) \
		$(GO) get -u github.com/alecthomas/gometalinter

.PHONY: all format vet build test clean $(GOPATH)/bin/gometalinter lint $(GOPATH)/bin/dep dep depcheck
