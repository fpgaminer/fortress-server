FROM rust:latest as builder

WORKDIR /usr/src/fortress-server
COPY src ./src
COPY Cargo.* ./
COPY migrations ./migrations

RUN cargo install --path .


# Build the final image
FROM debian:bullseye-slim

COPY --from=builder /usr/local/cargo/bin/fortress-server /usr/local/bin/

EXPOSE 8080

CMD ["fortress-server"]