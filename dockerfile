FROM rust as builder
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM gcr.io/distroless/cc
ENV CRAB_HOLE_DIR=/data
COPY --from=builder /app/target/release/crab-hole /
CMD ["./crab-hole"]