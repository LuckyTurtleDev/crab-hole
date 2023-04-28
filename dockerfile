FROM rust:alpine as builder
RUN apk update \
 && apk upgrade \
 && apk add --no-cache musl-dev
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM scratch
ENV CRAB_HOLE_DIR=/data
COPY --from=builder /app/target/release/crab-hole /
CMD ["./crab-hole"]