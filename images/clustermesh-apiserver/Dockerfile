# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

# distroless images are signed by cosign and can be verified using:
# $ cosign verify $IMAGE_NAME --certificate-oidc-issuer https://accounts.google.com --certificate-identity keyless@distroless.iam.gserviceaccount.com
ARG BASE_IMAGE=gcr.io/distroless/static:nonroot@sha256:627d6c5a23ad24e6bdff827f16c7b60e0289029b0c79e9f7ccd54ae3279fb45f
# These SHA256 digests are important for two reasons:
# 1. They 'pin' the container image to a specific version. Unlike a tag that can be changed at any future point, a
#    SHA265 hash cannot be modified. This increases the security of the build by protecting against a class of supply
#    chain attacks where an attacker has write access to our 3rd party dependency image registries.
# 2. These digests must be to the *overall* digest, not the digest for a specific image. This is because the images will
#    be architecture specific, but the overall digest will contain all of the architectures.
ARG GOLANG_IMAGE=docker.io/library/golang:1.24.5@sha256:ef5b4be1f94b36c90385abd9b6b4f201723ae28e71acacb76d00687333c17282
# We don't use ETCD_IMAGE because that's used in Makefile.defs to select a ETCD image approrpate for the *host platform*
# to run tests with.
ARG ETCD_SERVER_IMAGE=gcr.io/etcd-development/etcd:v3.6.4@sha256:5d10878e4fd4ebfdf82bc142fb044542a3ca514c0ee169277643a84d6816892a

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS builder

# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
# MODIFIERS are extra arguments to be passed to make at build time.
ARG MODIFIERS

WORKDIR /go/src/github.com/cilium/cilium
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    mkdir -p /out/${TARGETOS}/${TARGETARCH} && cp clustermesh-apiserver/etcd-config.yaml /out/${TARGETOS}/${TARGETARCH}/etcd-config.yaml
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${TARGETARCH} DESTDIR=/out/${TARGETOS}/${TARGETARCH} $(echo $MODIFIERS | tr -d '"') \
    build-container-clustermesh-apiserver install-container-binary-clustermesh-apiserver

WORKDIR /go/src/github.com/cilium/cilium
# licenses-all is a "script" that executes "go run" so its ARCH should be set
# to the same ARCH specified in the base image of this Docker stage (BUILDARCH)
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    make GOARCH=${BUILDARCH} licenses-all && mv LICENSE.all /out/${TARGETOS}/${TARGETARCH}

# BUILDPLATFORM is an automatic platform ARG enabled by Docker BuildKit.
# Represents the plataform where the build is happening, do not mix with
# TARGETARCH
FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} AS gops

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium \
    --mount=type=cache,target=/root/.cache \
    --mount=type=cache,target=/go/pkg \
    ./build-gops.sh

FROM --platform=${TARGETARCH} ${ETCD_SERVER_IMAGE} AS etcd

FROM ${BASE_IMAGE} AS release
# TARGETOS is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETOS
# TARGETARCH is an automatic platform ARG enabled by Docker BuildKit.
ARG TARGETARCH
LABEL maintainer="maintainer@cilium.io"
COPY --from=gops /out/${TARGETOS}/${TARGETARCH}/bin/gops /bin/gops
# While the etcd image uses /usr/local/bin, we're moving it to /usr/bin to keep consistency with the rest of our images.
# We also don't grab the etcdctl or etcdutl binaries, as we don't need them for our application.
COPY --from=etcd /usr/local/bin/etcd /usr/bin/etcd
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/etcd-config.yaml /var/lib/cilium/etcd-config.yaml
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/clustermesh-apiserver /usr/bin/clustermesh-apiserver
COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/LICENSE.all /LICENSE.all

# The Cilium Shell expects to be able to create a unix socket in /var/run/cilium
# Create the directory in advance to make sure that it has write privileges (we
# set 0777 permissions to the leaf directory), given that this container is
# typically run as a non-root user.
#
# tar --utc -tvf images/clustermesh-apiserver/var-run-cilium.tar
# drwxr-xr-x root/root         0 2025-06-15 00:00 var/
# drwxr-xr-x root/root         0 2025-06-15 00:00 var/run/
# drwxrwxrwx root/root         0 2025-06-15 00:00 var/run/cilium/
ADD images/clustermesh-apiserver/var-run-cilium.tar /

# Configure gops to use a temporary directory, to prevent permission
# issues depending on the UID configured to run the entrypoint.
ENV GOPS_CONFIG_DIR=/tmp/gops

ENTRYPOINT ["/usr/bin/clustermesh-apiserver"]
