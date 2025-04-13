use axum::{
    Json, Router,
    extract::{ConnectInfo, Query},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use maxminddb::Reader;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Error,
    net::{IpAddr, SocketAddr},
    path::Path,
};
use tokio::sync::OnceCell;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static IPV4_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
static IPV4_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

static IPV6_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
static IPV6_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

#[derive(Serialize, Deserialize, Debug)]
pub struct Asn {
    autonomous_system_number: usize,
    autonomous_system_organization: String,
    license: Option<String>,
    modifications: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Country {
    country_code: String,
}

#[derive(Serialize)]
struct RequestedAddress {
    ip: IpAddr,
    country: Option<Country>,
    asn: Option<Asn>,
}

impl RequestedAddress {
    pub fn default(ip: IpAddr) -> Self {
        RequestedAddress {
            ip,
            country: None,
            asn: None,
        }
    }

    #[warn(dead_code)]
    pub fn new(ip: IpAddr, country: Option<Country>, asn: Option<Asn>) -> Self {
        let mut rtn = RequestedAddress::default(ip);
        rtn.country = country;
        rtn.asn = asn;
        rtn
    }
}

async fn init_reader(path: impl AsRef<Path>) -> Result<Reader<Vec<u8>>, Error> {
    let content = tokio::fs::read(path).await.unwrap();
    let handle = tokio::spawn(async {
        let reader = maxminddb::Reader::from_source(content).unwrap();
        return Ok(reader);
    });
    handle.await.unwrap()
}

pub fn get_country(ip: IpAddr) -> Option<Country> {
    let reader = match ip {
        IpAddr::V4(_) => IPV4_COUNTRY.get().unwrap(),
        IpAddr::V6(_) => IPV6_COUNTRY.get().unwrap(),
    };
    match reader.lookup(ip).expect("Invalid IP address!") {
        Some(country) => Some(country),
        None => None,
    }
}

pub fn get_asn(ip: IpAddr) -> Option<Asn> {
    let reader = match ip {
        IpAddr::V4(_) => IPV4_ASN.get().unwrap(),
        IpAddr::V6(_) => IPV6_ASN.get().unwrap(),
    };
    match reader.lookup::<Asn>(ip).expect("Invalid IP address!") {
        Some(mut asn) => {
            asn.license = Some(String::from("CC BY 4.0 by RouteViews and DB-IP"));
            asn.modifications = Some(String::from(
                "https://github.com/sapics/ip-location-db/blob/main/asn/MODIFICATIONS",
            ));
            Some(asn)
        }
        None => None,
    }
}

#[derive(Deserialize)]
struct IndexParam {
    ip: Option<IpAddr>,
}

// TODO(neeythann): refactor this function
async fn index(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(param): Query<IndexParam>,
) -> Result<Json<RequestedAddress>, StatusCode> {
    // TODO(neeythann): handle private IP address. This should return a HTTP 415 if it's a private IP
    // address - `response.country` and `response.asn` attributes are currently set to null
    if let Some(ip) = param.ip {
        return Ok(Json(RequestedAddress::new(
            ip,
            get_country(ip),
            get_asn(ip),
        )));
    }

    let ip = addr.ip();
    let invalid_proxy: bool =
        !headers.contains_key("X-Forwarded-For") || headers.contains_key("CF-Connecting-IP");

    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local() {
                if invalid_proxy {
                    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }

                let x_forwarded_for: IpAddr = match headers.get("X-Forwarded-For") {
                    Some(ip) => ip.to_str().unwrap().parse().unwrap(),
                    None => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
                };

                return Ok(Json(RequestedAddress::new(
                    x_forwarded_for,
                    get_country(x_forwarded_for),
                    get_asn(x_forwarded_for),
                )));
            }

            Ok(Json(RequestedAddress::new(
                ip,
                get_country(ip),
                get_asn(ip),
            )))
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_loopback() || ipv6.is_unicast_link_local() || ipv6.is_unspecified() {
                if invalid_proxy {
                    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }
                let x_forwarded_for: IpAddr = match headers.get("X-Forwarded-For") {
                    Some(ip) => ip.to_str().unwrap().parse().unwrap(),
                    None => return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE),
                };

                return Ok(Json(RequestedAddress::new(
                    x_forwarded_for,
                    get_country(x_forwarded_for),
                    get_asn(x_forwarded_for),
                )));
            }
            Ok(Json(RequestedAddress::new(
                ip,
                get_country(ip),
                get_asn(ip),
            )))
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();
    tracing::event!(tracing::Level::INFO, "main");

    // TODO(neeythann): Vector map() (Reader, Path) instead
    IPV4_COUNTRY
        .get_or_init(|| async { init_reader("asn-country-ipv4.mmdb").await.unwrap() })
        .await;
    IPV4_ASN
        .get_or_init(|| async { init_reader("asn-ipv4.mmdb").await.unwrap() })
        .await;
    IPV6_COUNTRY
        .get_or_init(|| async { init_reader("asn-country-ipv6.mmdb").await.unwrap() })
        .await;
    IPV6_ASN
        .get_or_init(|| async { init_reader("asn-ipv6.mmdb").await.unwrap() })
        .await;

    let routes = Router::new().route("/", get(index));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    axum::serve(
        listener,
        routes.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
