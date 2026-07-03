# AGENTS.md – Quick guide for OpenCode agents

## Setup & dependencies
- MMDB data files (`asn-country-ipv4.mmdb`, `asn-country-ipv6.mmdb`, `asn-ipv4.mmdb`, `asn-ipv6.mmdb`) are **git‑ignored**; download them before building or testing (see `run.sh` or CI steps).
- `run.sh` is the container entrypoint: it fetches the MMDB files then executes `/app/ip-location-rs`.

## Building & local execution
- Build binary: `cargo build --release` → binary at `target/release/ip-location-rs`.
- Install globally: `cargo install --path .` → binary `ip-location-rs` available in PATH.
- Run binary directly (requires MMDB files in cwd): `target/release/ip-location-rs [--listen <IP:PORT>] [--experimental]`.
  - Default listen address is `0.0.0.0:80`.
  - `--experimental` (`-e`) toggles experimental routes (currently a placeholder).

## Docker usage
- Build image: `docker build -t ip-location-rs .`.
- Run container (exposes internal port 80): `docker run -d -p 8000:80 neeythann/ip-location-rs`.
- Host port `8000` maps to container port `80` (as defined in `Dockerfile`).
- The container’s `CMD` runs `run.sh`, which downloads MMDB files on first start.

## Testing
- CI test job downloads MMDB files before `cargo test --all-features`; replicate locally by running `./run.sh` (or the `wget` commands) first.
- Run tests: `cargo test --all-features`.

## API endpoints (as defined in `openapi.yaml`)
- `GET /` – returns JSON for the requester's IP (uses `X‑Real‑IP` header if present, otherwise socket address).
- `GET /ip/{ip_address}` – returns JSON for the supplied IPv4/IPv6 address; rejects private/loopback/unspecified addresses (415).
- `GET /AS/{asn}` – returns ASN info plus associated networks; `400` for invalid ASN.
- `GET /country/{country_code}` – returns country info plus networks; expects ISO‑3166‑1 alpha‑2 code; `400` for invalid input.

## Security note
- Service is intended to sit **behind a reverse proxy**; exposing it directly can lead to HTTP header‑injection attacks.

## Kubernetes deployment (ArgoCD manifests)
- Deployment uses image `neeythann/ip-location-rs:latest` and expects container port `80`.
- Service exposes port `80` as a `ClusterIP`.
- Application manifest points to `manifests/argo/` and creates namespace `ip-location-rs`.

## CI workflow quirks
- `test.yaml` explicitly downloads MMDB files; running tests without them will panic during `init_mmdb()`.
- `semgrep.yaml` runs automatic scans on pushes, PRs, and a daily schedule.
