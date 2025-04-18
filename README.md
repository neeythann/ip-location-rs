# ip-location-rs

ip-location-rs is a RESTful batteries-included IP information lookup microservice made with Rust.
It’s designed for high performance, easy deployment, and minimal dependencies.


## Installation

`docker run -d -p 8000:8000 neeythann/ip-location-rs`

## Building from Source

To build the project from source, you'll need [Rust](https://www.rust-lang.org/) and [cargo](https://doc.rust-lang.org/cargo/) installed.

```bash
git clone https://github.com/neeythann/ip-location-rs.git
cd ip-location-rs
cargo build --release
```

## Usage

For more information, please see the [openapi.yaml file spec](https://github.com/neeythann/ip-location-rs/blob/main/openapi.yaml)

This microservice only has one production-ready endpoint at the root (`/`) which accepts an `ip` query paramter
- If no `ip` query paramter is provided, the server will attempt to use:
  - The client's public IP address, if available;
  - or the `X-Forwarded-For` header (if present).
- Else would return a HTTP 415 error

### Experimental Endpoints

To enable experimental endpoints, pass the `--experimental` flag when executing the program

`GET /AS/{asn_number}` - returns a JSON response containing the ASN's details and associated networks  
`GET /country/{country_code}` - returns a JSON response containing the country details and associated networks

### Sample Usage

```bash
curl -s http://localhost:8000/?ip=1.1.1.1 -H 'X-Forwarded-For: 1.1.1.1' | jq
```

Which outputs:
```json
{
  "ip": "1.1.1.1",
  "country": {
    "country_code": "AU"
  },
  "asn": {
    "autonomous_system_number": 13335,
    "autonomous_system_organization": "Cloudflare, Inc.",
    "license": "CC BY 4.0 by RouteViews and DB-IP",
    "modifications": "https://github.com/sapics/ip-location-db/blob/main/asn/MODIFICATIONS"
  }
}
```

## Data Sources

This service uses [RouteViews](https://www.routeviews.org/routeviews/) and [DB-IP](https://db-ip.com/) MMDB files for geolocation, which are licensed under the Creative Commons Attribution 4.0 International License (CC BY 4.0).
You may download the databases from https://github.com/sapics/ip-location-db/tree/main/asn/ or see the `run.sh` file

## License

This repository is licensed under the MIT license - see the [LICENSE](https://github.com/neeythann/ip-location-rs/blob/main/LICENSE) file for more details.
