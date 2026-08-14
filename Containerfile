ARG TARGET=x86_64-unknown-linux-gnu
FROM docker.io/library/rust:1-slim-bullseye
ARG TARGET
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    rustup target add "$TARGET" && \
    cargo build --release --target "$TARGET" && \
    cp "target/$TARGET/release/cfw-build" /app/cfw-build
