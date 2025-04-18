use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query},
    http::{HeaderMap, StatusCode},
    routing::get,
};
use clap::Parser;
use ipnetwork::IpNetwork;
use maxminddb::{Reader, Within};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Error,
    net::{IpAddr, SocketAddr},
};
use tokio::sync::OnceCell;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static IPV4_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
static IPV4_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

static IPV6_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
static IPV6_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

#[derive(Parser, Debug)]
struct Args {
    #[arg(
        short,
        long,
        default_value_t = false,
        help = "enable experimental routes"
    )]
    experimental: bool,

    #[arg(
        short,
        long,
        default_value = "0.0.0.0:8000",
        help = "A socket to listen for the server"
    )]
    listen: SocketAddr,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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

async fn init_reader(path: impl AsRef<std::path::Path>) -> Result<Reader<Vec<u8>>, Error> {
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnResponse {
    asn: Asn,
    networks: Option<Vec<String>>,
}

impl AsnResponse {
    pub fn default(asn: Asn) -> Self {
        Self::new(asn, None)
    }

    pub fn new(asn: Asn, networks: Option<Vec<String>>) -> Self {
        AsnResponse { asn, networks }
    }
}

// TODO(neeythann):
// - validate Path(asn) with ISO 3166-1 alpha-2
// - cache this result at startup
async fn endpoint_get_asn(Path(asn): Path<usize>) -> Result<Json<AsnResponse>, StatusCode> {
    let network4: IpNetwork = "0.0.0.0/0".parse().unwrap();
    let network6: IpNetwork = "::0/0".parse().unwrap();
    let mut net: Vec<String> = vec![];

    let mut asn_info: Option<Asn> = None;

    let mut iter: Within<Asn, _> = IPV4_ASN.get().unwrap().within(network4).unwrap();
    while let Some(next) = iter.next() {
        let item = next.unwrap();
        if item.info.autonomous_system_number != asn {
            continue;
        }

        if asn_info.is_none() {
            asn_info = Some(item.info.clone());
        }
        net.push(item.ip_net.to_string())
    }
    iter = IPV6_ASN.get().unwrap().within(network6).unwrap();
    while let Some(next) = iter.next() {
        let item = next.unwrap();
        if item.info.autonomous_system_number != asn {
            continue;
        }
        net.push(item.ip_net.to_string())
    }

    Ok(Json(AsnResponse::new(asn_info.unwrap(), Some(net))))
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CountryResponse {
    country: Country,
    networks: Option<Vec<String>>,
}

// TODO(neeythann):
// - validate Path(country) with ISO 3166-1 alpha-2
// - cache this result at startup
async fn endpoint_get_country(
    Path(country_code): Path<String>,
) -> Result<Json<CountryResponse>, StatusCode> {
    if country_code.len() != 2 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut net: Vec<String> = vec![];
    let mut country_info: Option<Country> = None;

    let network4: IpNetwork = "0.0.0.0/0".parse().unwrap();
    let mut iter: Within<Country, _> = IPV4_COUNTRY.get().unwrap().within(network4).unwrap();
    while let Some(next) = iter.next() {
        let item = next.unwrap();
        if item.info.country_code != country_code {
            continue;
        }

        if country_info.is_none() {
            country_info = Some(item.info);
        }
        net.push(item.ip_net.to_string())
    }

    let network6: IpNetwork = "::0/0".parse().unwrap();
    iter = IPV6_COUNTRY.get().unwrap().within(network6).unwrap();
    while let Some(next) = iter.next() {
        let item = next.unwrap();
        if item.info.country_code != country_code {
            continue;
        }
        net.push(item.ip_net.to_string())
    }

    Ok(Json(CountryResponse {
        country: country_info.unwrap(),
        networks: Some(net),
    }))
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
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

    let mut routes = Router::new().route("/", get(index));

    if args.experimental {
        routes = routes.merge(
            Router::new()
                .route("/AS/{asn}", get(endpoint_get_asn))
                .route("/country/{country_code}", get(endpoint_get_country)),
        );
    }
    let listener = tokio::net::TcpListener::bind(args.listen).await.unwrap();
    axum::serve(
        listener,
        routes.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
