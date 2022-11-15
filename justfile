default:
    @just --list

vmlinux:
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./src/bpf/vmlinux.h