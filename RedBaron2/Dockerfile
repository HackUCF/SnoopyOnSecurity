FROM rust:1.92-slim-bookworm AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    make \
    gcc \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    musl-tools \
  && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /src
COPY . .

RUN test -f rb2-ebpf/libbpf/src/Makefile
RUN make -C rb2-ebpf/libbpf/src install_headers PREFIX=/usr INCLUDEDIR=/usr/include

ENV CARGO_BUILD_TARGET=x86_64-unknown-linux-musl \
    RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-lm"

RUN cargo build --release --target x86_64-unknown-linux-musl
