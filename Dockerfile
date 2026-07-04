FROM --platform=$BUILDPLATFORM rust:1.85-bullseye AS builder
ARG TARGETPLATFORM
WORKDIR /usr/src/myapp
COPY . .

# Install the arm64 cross-linker and Rust target only when building for arm64.
# The builder stage itself always runs on the runner's native arch ($BUILDPLATFORM),
# so cargo compiles natively without QEMU emulation regardless of the target.
RUN case "$TARGETPLATFORM" in \
      linux/arm64) \
        apt-get update && apt-get install -y --no-install-recommends \
          gcc-aarch64-linux-gnu \
          libc6-dev-arm64-cross && \
        rustup target add aarch64-unknown-linux-gnu ;; \
    esac

ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

# Build for the requested target arch and normalise the binary path so the
# runtime stage's COPY is arch-agnostic.
RUN case "$TARGETPLATFORM" in \
      linux/arm64) \
        cargo build --release --target aarch64-unknown-linux-gnu && \
        cp target/aarch64-unknown-linux-gnu/release/ip-location-rs \
           /usr/src/myapp/ip-location-rs-bin ;; \
      *) \
        cargo build --release && \
        cp target/release/ip-location-rs /usr/src/myapp/ip-location-rs-bin ;; \
    esac

FROM debian:bookworm-slim
RUN adduser --disabled-password --gecos '' app
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*
USER app
WORKDIR /app
COPY --from=builder /usr/src/myapp/ip-location-rs-bin /app/ip-location-rs
COPY --from=builder /usr/src/myapp/run.sh .
COPY --from=builder /usr/src/myapp/DBIP-LICENSE .
COPY --from=builder /usr/src/myapp/ROUTEVIEWS-LICENSE .

EXPOSE 80
CMD ["bash", "./run.sh"]
