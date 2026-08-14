ARG TARGET=x86_64-unknown-linux-gnu
ARG SUITE=bullseye
FROM docker.io/library/rust:1-slim-${SUITE}
ARG TARGET

# binutils reads the glibc floor below; the cross toolchain is what links a
# foreign target, and cargo needs telling which linker to use for it.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends binutils && \
    case "$TARGET" in \
      aarch64-*) apt-get install -y --no-install-recommends \
                   gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;; \
    esac
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

WORKDIR /app

# Cargo.lock is not tracked, so it is copied only when the caller staged one.
# build-helper.sh stages the context; the repo root would ship target/ and the
# test captures.
COPY . ./

# The glibc floor is read off the binary rather than assumed: it moves with the
# base image, and one that is too high runs on the build machine and dies at
# exec everywhere older.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/local/cargo/git,id=cargo-git \
    rustup target add "$TARGET" && \
    cargo build --release --target "$TARGET" && \
    cp "target/$TARGET/release/cfw-build" /app/cfw-build && \
    objdump -T /app/cfw-build \
      | sed -n 's/.*GLIBC_\([0-9][0-9.]*\).*/\1/p' \
      | sort -Vu | tail -1 > /app/glibc-floor
