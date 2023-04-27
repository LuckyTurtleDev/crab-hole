FROM rust as builder
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM gcr.io/distroless/cc
COPY --from=builder /app/target/release/crab-hole /
CMD ["./crab-hole"]