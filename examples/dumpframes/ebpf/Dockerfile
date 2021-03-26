FROM centos:8

RUN dnf install -y make cmake gcc gdb clang llvm clang-devel llvm-devel autoconf libtool kernel-devel libbpf elfutils-libelf-devel elfutils-devel

RUN /bin/bash -c " \
    curl -fsSL https://golang.org/dl/go1.16.2.linux-amd64.tar.gz -o /tmp/golang.tar.gz && \
    tar -C /usr/local -xzf /tmp/golang.tar.gz"

ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin/

RUN dnf -y install git

RUN go get github.com/cilium/ebpf/cmd/bpf2go@v0.4.0

ENTRYPOINT ["bash", "-c", "cd /target/examples/dumpframes/ebpf && go generate"]
