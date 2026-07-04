use crate::ProxyType;
use crate::db::{get_asn, get_country};
use crate::models::RequestedAddress;
use axum::{
    Extension, Json,
    extract::{ConnectInfo, Path},
    http::{HeaderMap, StatusCode},
};
use std::net::{IpAddr, SocketAddr};

// SECURITY CONSIDERATION: This microservice is meant to be deployed behind
// a reverse proxy. Deploying it direcly makes it vulnerable to HTTP Header Injection
// attacks, which is not (and will not be) supported anytime in the future.
//
// Which header (if any) is trusted for the client's real IP is controlled by
// the `--proxy` CLI flag (see `ProxyType` in `main.rs`). When the selected
// header is absent or malformed the handler falls back to the connected
// socket address rather than erroring, so a misconfigured proxy never turns
// a successful lookup into a 4xx/5xx.
pub async fn index(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(proxy): Extension<ProxyType>,
    headers: HeaderMap,
) -> Result<Json<RequestedAddress>, StatusCode> {
    let ip = proxy.client_ip(&headers).unwrap_or_else(|| addr.ip());

    Ok(Json(RequestedAddress::new(
        ip,
        get_country(ip),
        get_asn(ip),
    )))
}

pub async fn endpoint_get_ip(Path(ip): Path<IpAddr>) -> Result<Json<RequestedAddress>, StatusCode> {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_unspecified()
                || ipv4.is_broadcast()
            {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            Ok(Json(RequestedAddress {
                ip,
                country: get_country(ip),
                asn: get_asn(ip),
            }))
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback()
                || ipv6.is_multicast()
                || ipv6.is_unspecified()
                || ipv6.is_unique_local()
                || ipv6.is_unicast_link_local()
            {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            Ok(Json(RequestedAddress {
                ip,
                country: get_country(ip),
                asn: get_asn(ip),
            }))
        }
    }
}
