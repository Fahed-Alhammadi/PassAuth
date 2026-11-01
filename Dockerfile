# syntax=docker/dockerfile:1.7
#
# PassAuth server image.
# - Cross-compiles natively for amd64/arm64 (no QEMU emulation for Rust).
# - Runtime is distroless (no shell, no package manager) and never runs as root:
#   default uid/gid 1000, overridable at run time (compose `user: ${PUID}:${PGID}`).

ARG RUST_VERSION=1.99

# ------------------------------------------------- core crypto → WebAssembly
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS wasm
RUN rustup target add wasm32-unknown-unknown
WORKDIR /src
COPY Cargo.lock ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    v="$(grep -A3 'name = "wasm-bindgen"' Cargo.lock | grep -m1 version | cut -d'"' -f2)" && \
    cargo install wasm-bindgen-cli --version "$v" --locked
COPY Cargo.toml ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY scripts ./scripts
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=passauth-wasm-target \
    scripts/build-wasm.sh /wasm-out

# ---------------------------------------------------------------- web vault
FROM --platform=$BUILDPLATFORM node:24-bookworm-slim AS web
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY web/ ./
COPY --from=wasm /wasm-out ./src/wasm
RUN pnpm build

# ------------------------------------------------------------------- server
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-bookworm AS builder
ARG TARGETARCH
ARG BUILDARCH
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu; gcc=x86-64-linux-gnu; dpkg=amd64 ;; \
      arm64) target=aarch64-unknown-linux-gnu; gcc=aarch64-linux-gnu; dpkg=arm64 ;; \
      *) echo "unsupported arch $TARGETARCH"; exit 1 ;; \
    esac; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends "gcc-$gcc" "libc6-dev-$dpkg-cross"; \
      rm -rf /var/lib/apt/lists/*; \
      echo "$gcc-gcc" > /linker; \
    else \
      echo "gcc" > /linker; \
    fi; \
    echo "$target" > /target; \
    rustup target add "$target"

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target,id=passauth-target-${TARGETARCH} \
    set -eux; \
    target="$(cat /target)"; linker="$(cat /linker)"; \
    env_target="$(echo "$target" | tr 'a-z-' 'A-Z_')"; \
    export "CARGO_TARGET_${env_target}_LINKER=$linker" "CC_$(echo "$target" | tr '-' '_')=$linker"; \
    cargo build --release --locked -p passauth-server --target "$target"; \
    cp "target/$target/release/passauth-server" /passauth-server

# Directories owned by the default runtime user (distroless has no chown/mkdir).
RUN mkdir -p /rootfs/data /rootfs/tmp && chmod 1777 /rootfs/tmp

# ------------------------------------------------------------------ runtime
FROM gcr.io/distroless/cc-debian12

ARG VERSION=dev
LABEL org.opencontainers.image.title="PassAuth" \
      org.opencontainers.image.description="Self-hosted, zero-knowledge password manager" \
      org.opencontainers.image.source="https://github.com/Fahed-Alhammadi/PassAuth" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="UNLICENSED"

COPY --from=builder --chown=1000:1000 /rootfs/ /
COPY --from=builder /passauth-server /usr/local/bin/passauth-server
COPY --from=web /web/dist /web-vault

ENV BIND=0.0.0.0:8080 \
    DATABASE_URL=sqlite:///data/passauth.db?mode=rwc \
    WEB_VAULT_DIR=/web-vault

USER 1000:1000
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/passauth-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/passauth-server"]
CMD ["serve"]
