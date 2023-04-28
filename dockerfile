FROM rust:alpine as builder
RUN apk update \
 && apk upgrade \
 && apk add --no-cache musl-dev
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