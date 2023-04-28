FROM alpine as builder
ARG TARGETPLATFORM
RUN apk update \
 && apk upgrade \
 && apk add --no-cache \
    musl-dev \
    bash \
    cargo \
    curl \
    curl-dev \
    openssl-dev>3 \
    perl \
    zlib-dev \
    zstd-dev
RUN set -eux; \
    if [[ $TARGETPLATFORM == "linux/amd64" ]]; then target="x86_64-unknown-linux-musl"; fi; \
    if [[ $TARGETPLATFORM == "linux/arm/v7" ]]; then target="armv7-unknown-linux-musleabihf"; fi; \
    if [[ $TARGETPLATFORM == "linux/arm64/v8" ]]; then target="aarch64-unknown-linux-musl"; fi; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | /bin/bash -s -- -y --default-host $target
ENV PATH "$PATH:/root/.cargo/bin"
WORKDIR /app
COPY . /app
RUN \
    --mount=type=cache,target=/app/target \
    cargo build --release \
 && cp /app/target/release/crab-hole /crab-hole


FROM scratch
ENV CRAB_HOLE_DIR=/data
COPY --from=builder /crab-hole /
CMD ["./crab-hole"]
