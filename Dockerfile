# syntax=docker/dockerfile:1.7
#
# meshd — the internal service-discovery node (pkarr relay + authoritative DNS zone).
#
#   docker build -t meshd:local .
#   docker run --rm -p 127.0.0.1:6881:6881 -p 127.0.0.1:5353:5353/udp -v meshd-data:/var/lib/meshd meshd:local
#
# Some dependencies are private git repositories. Give the build a GitHub token as a BuildKit
# secret; it is written to a git config for that one RUN and removed in the same RUN, so it is in
# no layer and not in the final image:
#
#   docker build --secret id=gh_token,env=GH_TOKEN -t meshd:local .
#
# With nothing private to fetch the secret may be omitted.
#
# This Dockerfile is the fallback for a builder without Nix. The primary path is the flake
# (`nix build .#meshd-oci`): it needs no token at build time (the private git dependencies are flake
# inputs), carries the SBOM and a reproducibility check, and replaces the old Dockerfile.offline.
#
# The runtime image is distroless (glibc, no shell, no package manager), runs as a non-root user,
# and carries only the one binary. `--healthcheck` is built into meshd so no curl is needed.

ARG RUST_VERSION=1.97

# ---------------------------------------------------------------- build
# Pinned by digest (the multi-arch index of rust:1.97-bookworm); bump the tag and the digest together:
#   docker buildx imagetools inspect rust:1.97-bookworm
FROM rust:${RUST_VERSION}-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS build

# aws-lc-sys (the crypto provider under rustls) needs cmake to build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Cargo's own git client does not read git config the way git does; the CLI does, and is what
# honours the token rewrite below.
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true \
    CARGO_TERM_COLOR=never

# --locked: the image is built from exactly the Cargo.lock in the repository; a stale lock is a
# build failure, not a silent re-resolve.
RUN --mount=type=secret,id=gh_token,required=false \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    set -eu; \
    trap 'rm -f "$HOME/.gitconfig"' EXIT; \
    if [ -s /run/secrets/gh_token ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf "https://github.com/"; \
    fi; \
    cargo build --release --locked --bin meshd; \
    install -D target/release/meshd /out/meshd; \
    install -d -m 0750 /out/data

# ---------------------------------------------------------------- runtime
# Pinned by digest (gcr.io/distroless/cc-debian12:nonroot).
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime

LABEL org.opencontainers.image.title="meshd" \
      org.opencontainers.image.description="Internal service discovery: a pkarr relay and an authoritative DNS zone for dialkey-published services." \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /out/meshd /usr/local/bin/meshd
# Records persist here. Owned by the image's non-root user (65532) so a fresh named volume is writable.
COPY --from=build --chown=65532:65532 /out/data /var/lib/meshd

ENV MESHD_HTTP_BIND=0.0.0.0:6881 \
    MESHD_DNS_BIND=0.0.0.0:5353 \
    MESHD_DATA_DIR=/var/lib/meshd \
    MESHD_ZONE=mesh.internal

# 6881 is the relay (HTTP); 5353 is DNS over UDP and TCP (53 needs a privilege this image does not
# have: map host 53 to it instead).
EXPOSE 6881/tcp 5353/udp 5353/tcp
VOLUME ["/var/lib/meshd"]

USER nonroot
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/meshd", "--healthcheck"]
ENTRYPOINT ["/usr/local/bin/meshd"]
