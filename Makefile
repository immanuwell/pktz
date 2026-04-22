.PHONY: all build generate vmlinux install clean

BINARY   := pktz
MODULE   := github.com/immanuwell/pktz
BPF_SRC  := bpf/pktz.c
VMLINUX  := bpf/vmlinux.h
PREFIX   ?= /usr/local

all: generate build

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

generate: vmlinux
	go generate ./internal/collector/...

build:
	go build -o $(BINARY) .

install: build
	sudo install -m 0755 $(BINARY) $(PREFIX)/bin/$(BINARY)

clean:
	rm -f $(BINARY) $(VMLINUX)
	rm -f internal/collector/pktz_bpf*.go internal/collector/pktz_bpf*.o
