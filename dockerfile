FROM alpine as builder
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
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | /bin/bash -s -- -y
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
