# ip-location-rs

ip-location-rs is a RESTful batteries-included IP information lookup microservice made with Rust.
It’s designed for high performance, easy deployment, and minimal dependencies.

**IMPORTANT: THIS MICROSERVICE IS MEANT TO BE DEPLOYED WITHIN A REVERSE PROXY. DEPLOYING
IT DIRECTLY MAKES IT VULNERABLE TO [HTTP HEADER INJECTION](https://en.wikipedia.org/wiki/HTTP_header_injection), WHICH IS CURRENTLY NOT (AND WILL NOT BE) SUPPORTED ANYTIME IN THE FUTURE**

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

`GET /` - returns a JSON response containing the current user's IP address AS and country details  
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
