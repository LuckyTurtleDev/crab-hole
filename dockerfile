FROM rust as builder
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM scratch
COPY --from=builder /app/target/release/crab-hole /
CMD ["crab-hole"]