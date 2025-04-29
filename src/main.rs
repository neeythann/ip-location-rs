use axum::{
    Json, Router,
    extract::{ConnectInfo, Path},
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
use tokio::{sync::OnceCell, task::yield_now};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static IPV4_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
static IPV4_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

static IPV6_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
static IPV6_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
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

// TODO(neeythann): refactor this function
async fn index(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<Json<RequestedAddress>, StatusCode> {
    // SECURITY CONSIDERATION: This microservice is meant to be deployed behind
    // a reverse proxy. Deploying it direcly makes it vulnerable to HTTP Header Injection
    // attacks, which is not (and will not be) supported anytime in the future
    let maybe_ip: Option<IpAddr> = match headers.get("X-Real-IP") {
        Some(ip) => Some(ip.to_str().unwrap().parse().unwrap()),
        None => None,
    };

    match maybe_ip {
        Some(ip) => {
            return Ok(Json(RequestedAddress::new(
                ip,
                get_country(ip),
                get_asn(ip),
            )));
        }
        None => {
            return Ok(Json(RequestedAddress::new(
                addr.ip(),
                get_country(addr.ip()),
                get_asn(addr.ip()),
            )));
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
// - validate Path(asn)
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
        net.push(item.ip_net.to_string());
        yield_now().await;
    }
    iter = IPV6_ASN.get().unwrap().within(network6).unwrap();
    while let Some(next) = iter.next() {
        let item = next.unwrap();
        if item.info.autonomous_system_number != asn {
            continue;
        }
        net.push(item.ip_net.to_string());
        yield_now().await;
    }

    if asn_info.is_none() {
        return Err(StatusCode::BAD_REQUEST);
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
    if country_code.len() != 2 || !country_code.bytes().all(|c| matches!(c, b'A'..=b'Z')) {
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
        net.push(item.ip_net.to_string());
        yield_now().await;
    }

    let network6: IpNetwork = "::0/0".parse().unwrap();
    iter = IPV6_COUNTRY.get().unwrap().within(network6).unwrap();
    while let Some(next) = iter.next() {
        let item = next.unwrap();
        if item.info.country_code != country_code {
            continue;
        }
        net.push(item.ip_net.to_string());
        yield_now().await;
    }

    // TODO(neeythann): prematurely check `Path(country)` at the start
    // if it's an ISO 3166-1 alpha-2 country code
    if country_info.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Json(CountryResponse {
        country: country_info.unwrap(),
        networks: Some(net),
    }))
}

async fn endpoint_get_ip(Path(ip): Path<IpAddr>) -> Result<Json<RequestedAddress>, StatusCode> {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_unspecified()
                || ipv4.is_broadcast()
            {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            return Ok(Json(RequestedAddress {
                ip,
                country: get_country(ip),
                asn: get_asn(ip),
            }));
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
            return Ok(Json(RequestedAddress {
                ip,
                country: get_country(ip),
                asn: get_asn(ip),
            }));
        }
    }
}

async fn init_mmdb() {
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
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();
    tracing::event!(tracing::Level::INFO, "main");

    init_mmdb().await;

    let routes = Router::new()
        .route("/", get(index))
        .route("/ip/{ip_address}", get(endpoint_get_ip))
        .route("/AS/{asn}", get(endpoint_get_asn))
        .route("/country/{country_code}", get(endpoint_get_country));

    // placeholder for now
    if args.experimental {}
    let listener = tokio::net::TcpListener::bind(args.listen).await.unwrap();
    axum::serve(
        listener,
        routes.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::connect_info::MockConnectInfo,
        http::{self, Request, StatusCode},
    };
    use tower::{Service, ServiceExt}; // for `call`, `oneshot`, and `ready`

    #[tokio::test]
    async fn oncecell_not_none() {
        init_mmdb().await;
        IPV4_ASN.get().unwrap();
        IPV6_ASN.get().unwrap();
        IPV4_COUNTRY.get().unwrap();
        IPV6_COUNTRY.get().unwrap();
    }

    #[tokio::test]
    async fn index_header_xforwardedfor_ip_ipv4() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo("127.0.0.1:8000".parse::<SocketAddr>()))
            .into_service();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("X-Forwarded-For", "1.1.1.1")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn index_header_xforwardedfor_ip_ipv6() {
        init_mmdb().await;
        let mut app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo("127.0.0.1:8000".parse::<SocketAddr>()))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("X-Forwarded-For", "2606:4700:4700::1111")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.ready().await.unwrap().call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn index_header_cfconnectingip_ip_ipv4() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo("127.0.0.1:8000".parse::<SocketAddr>()))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("CF-Connecting-IP", "1.1.1.1")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE)
    }

    #[tokio::test]
    async fn index_header_cfconnectingip_ip_ipv6() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo("127.0.0.1".parse::<SocketAddr>()))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("CF-Connecting-IP", "2606:4700:4700::1111")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE)
    }

    #[tokio::test]
    async fn asn_valid() {
        init_mmdb().await;
        let app = Router::new()
            .route("/AS/{asn_number}", get(endpoint_get_asn))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/AS/1")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn asn_invalid_number() {
        init_mmdb().await;
        let app = Router::new()
            .route("/AS/{asn_number}", get(endpoint_get_asn))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/AS/9999999")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST)
    }

    #[tokio::test]
    async fn asn_invalid_type() {
        init_mmdb().await;
        let app = Router::new()
            .route("/AS/{asn_number}", get(endpoint_get_asn))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/AS/foobar")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST)
    }

    #[tokio::test]
    async fn country_valid() {
        init_mmdb().await;
        let app = Router::new()
            .route("/country/{country_code}", get(endpoint_get_country))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/country/PH")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn country_invalid_lowercase() {
        init_mmdb().await;
        let app = Router::new()
            .route("/country/{country_code}", get(endpoint_get_country))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/country/ph")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST)
    }

    #[tokio::test]
    async fn country_invalid() {
        init_mmdb().await;
        let app = Router::new()
            .route("/country/{country_code}", get(endpoint_get_country))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/country/foobar")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST)
    }

    #[tokio::test]
    async fn ip_ipv4_valid() {
        init_mmdb().await;
        let app = Router::new()
            .route("/ip/{ip_address}", get(endpoint_get_ip))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/ip/1.1.1.1")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn ip_invalid() {
        init_mmdb().await;
        let app = Router::new()
            .route("/ip/{ip_address}", get(endpoint_get_ip))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/ip/foobar")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST)
    }

    #[tokio::test]
    async fn ip_ipv4_invalid() {
        init_mmdb().await;
        let app = Router::new()
            .route("/ip/{ip_address}", get(endpoint_get_ip))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/ip/1.1.1")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST)
    }

    #[tokio::test]
    async fn ip_ipv6_valid() {
        init_mmdb().await;
        let app = Router::new()
            .route("/ip/{ip_address}", get(endpoint_get_ip))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/ip/2606:4700:4700::1111")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn ip_ipv6_invalid() {
        init_mmdb().await;
        let app = Router::new()
            .route("/ip/{ip_address}", get(endpoint_get_ip))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/ip/2606:4700:4700:")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST)
    }
}
