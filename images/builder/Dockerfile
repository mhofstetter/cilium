# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG COMPILERS_IMAGE=quay.io/cilium/image-compilers:f51ffb467692a59696b144dfe2f1ddeae1bb6bca@sha256:32f5f098d74db46c9d0405e25236828d22b7e3d7006387f9287b4aee48bc85c6
ARG CILIUM_RUNTIME_IMAGE=quay.io/cilium/cilium-runtime:da5e15659730a6ef7b81f8c541da43c0418db170@sha256:a6ca35ea4950bef4152525b48d381d23848cf94398332f040d9b4bac48aeb5bf
ARG TESTER_IMAGE=quay.io/cilium/image-tester:0a7ee27812441d95926aec83929d97e93ce96aae@sha256:e96542b4f71dbc9cbe77feaf5b1fa9bd5e13122ee6418094731212f1c5667c67
ARG GOLANG_IMAGE=docker.io/library/golang:1.24.4@sha256:20a022e5112a144aa7b7aeb3f22ebf2cdaefcc4aac0d64e8deeee8cdc18b9c0f
ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:1747754567-1d8e3ec@sha256:acbb945f89906996273dda37a51bb9f52a61cfccd369dcbe5ddf9409cc97bd88

FROM ${COMPILERS_IMAGE} AS compilers-image

FROM ${GOLANG_IMAGE} AS golang-dist

FROM ${CILIUM_LLVM_IMAGE} AS llvm-dist

FROM ${CILIUM_RUNTIME_IMAGE} AS rootfs

# Change the number to force the generation of a new git-tree SHA. Useful when
# we want to re-run 'apt-get upgrade' for stale images.
ENV FORCE_BUILD=1

# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
RUN \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
      # Install cross tools for both arm64 on amd64
      gcc-aarch64-linux-gnu \
      g++-aarch64-linux-gnu \
      libc6-dev-arm64-cross \
      binutils-aarch64-linux-gnu \
      gcc-x86-64-linux-gnu \
      g++-x86-64-linux-gnu \
      libc6-dev-amd64-cross \
      binutils-x86-64-linux-gnu \
      # Dependencies to unzip protoc
      unzip \
      # Base Cilium-build dependencies
      binutils \
      coreutils \
      curl \
      gcc \
      git \
      libc6-dev \
      make \
      ccache && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=compilers-image /usr/lib/aarch64-linux-gnu /usr/lib/aarch64-linux-gnu

COPY --from=golang-dist /usr/local/go /usr/local/go
RUN mkdir -p /go
ENV GOROOT /usr/local/go
ENV GOPATH /go
ENV PATH "${GOROOT}/bin:${GOPATH}/bin:${PATH}"

RUN GOARCH=${TARGETARCH} CGO_ENABLED=0 go install github.com/go-delve/delve/cmd/dlv@latest

WORKDIR /go/src/github.com/cilium/cilium/images/builder
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./install-gitconfig.sh

WORKDIR /go/src/github.com/cilium/cilium/images/builder
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    ./build-debug-wrapper.sh

WORKDIR /go/src/github.com/cilium/cilium/images/builder
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./install-protoc.sh

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./install-protoplugins.sh

WORKDIR /go/src/github.com/cilium/cilium/images/builder
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/builder \
    ./install-test-formatters.sh

# used to facilitate the verifier tests
COPY --from=llvm-dist /usr/local/bin/llvm-objcopy /bin/

# Create a cache directory with 777 so that we can run the builder image and
# compile golang code from any UID.
RUN mkdir -p /.cache && chmod 777 /.cache && \
    mkdir -p /go/bin && chmod 777 /go/bin

FROM ${TESTER_IMAGE} as test
COPY --from=rootfs / /
COPY test /test
RUN /test/bin/cst

# this image is large, and re-using layers is beneficial,
# so final images is not squashed
FROM rootfs as release
LABEL maintainer="maintainer@cilium.io"
WORKDIR /go/src/github.com/cilium/cilium
