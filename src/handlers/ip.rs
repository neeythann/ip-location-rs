use crate::db::{get_asn, get_country};
use crate::models::RequestedAddress;
use axum::{
    Json,
    extract::{ConnectInfo, Path},
    http::{HeaderMap, StatusCode},
};
use std::net::{IpAddr, SocketAddr};

// SECURITY CONSIDERATION: This microservice is meant to be deployed behind
// a reverse proxy. Deploying it direcly makes it vulnerable to HTTP Header Injection
// attacks, which is not (and will not be) supported anytime in the future
pub async fn index(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<RequestedAddress>, StatusCode> {
    let maybe_ip: Option<IpAddr> = match headers.get("X-Real-IP") {
        Some(ip) => Some(ip.to_str().unwrap().parse().unwrap()),
        None => None,
    };

    match maybe_ip {
        Some(ip) => Ok(Json(RequestedAddress::new(
            ip,
            get_country(ip),
            get_asn(ip),
        ))),
        None => Ok(Json(RequestedAddress::new(
            addr.ip(),
            get_country(addr.ip()),
            get_asn(addr.ip()),
        ))),
    }
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
