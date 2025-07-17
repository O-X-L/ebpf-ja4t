#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")"

mkdir -p ../build/

docker build -t ebpf-compiler -f ../docker/Dockerfile_build .

docker run --rm -v "$(pwd)/..":/app ebpf-compiler /bin/bash -c "\
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > /app/build/vmlinux.h && \
    clang -O2 -target bpf -c /app/src/ja4t_ebpf.c -o /app/build/ja4t_ebpf.o -I/app/build -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/linux -I/usr/include && \
    chmod 666 /app/build/*"

go build -o ja4t_collector ../src/ja4t_collector.go

echo 'DONE:'
ls -l ../build/
