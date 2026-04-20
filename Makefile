.PHONY: all build generate vmlinux clean

BINARY   := pktz
MODULE   := github.com/immanuwell/pktz
BPF_SRC  := bpf/pktz.c
VMLINUX  := bpf/vmlinux.h

all: generate build

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

generate: vmlinux
	go generate ./internal/collector/...

build:
	go build -o $(BINARY) .

clean:
	rm -f $(BINARY) $(VMLINUX)
	rm -f internal/collector/pktz_bpf*.go internal/collector/pktz_bpf*.o
