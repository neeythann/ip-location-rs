FROM rust:1.85-bullseye AS builder
WORKDIR /usr/src/myapp
COPY . .
RUN cargo install --path .

FROM debian:bullseye-slim
RUN adduser --disabled-password --gecos '' app
RUN apt-get update && apt-get install -y wget && rm -rf /var/lib/apt/lists/*
USER app
WORKDIR /app
COPY --from=builder /usr/local/cargo/bin/ip-location-rs .
COPY --from=builder /usr/src/myapp/run.sh .
COPY --from=builder /usr/src/myapp/DBIP-LICENSE .
COPY --from=builder /usr/src/myapp/ROUTEVIEWS-LICENSE .

EXPOSE 8000
CMD ["bash", "./run.sh"]

