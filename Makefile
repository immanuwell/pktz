.PHONY: all build test vet check release-build generate vmlinux install clean

BINARY   := pktz
MODULE   := github.com/immanuwell/pktz
BPF_SRC  := bpf/pktz.c
VMLINUX  := bpf/vmlinux.h
PREFIX   ?= /usr/local
DIST_DIR ?= dist

all: generate build

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

generate: vmlinux
	go generate ./internal/collector/...

build:
	go build -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

check: test vet build

release-build:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)-linux-arm64 .
	GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o $(DIST_DIR)/$(BINARY)-linux-armv7 .

install: build
	sudo install -m 0755 $(BINARY) $(PREFIX)/bin/$(BINARY)

clean:
	rm -f $(BINARY) $(VMLINUX)
	rm -f internal/collector/pktz_bpf*.go internal/collector/pktz_bpf*.o
