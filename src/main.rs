pub mod db;
pub mod handlers;
pub mod models;

use axum::{
    Extension, Router, routing::get,
    http::HeaderMap,
};
use clap::{Parser, ValueEnum};
use handlers::{
    asn::endpoint_get_asn,
    country::endpoint_get_country,
    ip::{endpoint_get_ip, index},
};
use std::net::{IpAddr, SocketAddr};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ProxyType {
    /// Read the client IP from the `CF-Connecting-IP` header (Cloudflare).
    #[value(name = "cf-connecting-ip")]
    CfConnectingIp,
    /// Read the client IP from the leftmost entry of the `X-Forwarded-For` header.
    #[value(name = "x-forwarded-for")]
    XForwardedFor,
    /// Read the client IP from the `X-Real-IP` header.
    #[value(name = "x-real-ip")]
    XRealIp,
    /// Ignore all headers and use the connected socket address.
    #[value(name = "none")]
    None,
}

impl ProxyType {
    /// Returns the configured client IP, falling back to `None` (caller should
    /// use the connected socket address) when the selected header is absent or
    /// holds a value that is not a valid `IpAddr`.
    pub fn client_ip(self, headers: &HeaderMap) -> Option<IpAddr> {
        let header_name = match self {
            ProxyType::CfConnectingIp => "CF-Connecting-IP",
            ProxyType::XForwardedFor => "X-Forwarded-For",
            ProxyType::XRealIp => "X-Real-IP",
            ProxyType::None => return None,
        };

        let value = headers.get(header_name)?.to_str().ok()?;
        let candidate = match self {
            // X-Forwarded-For is a comma-separated list; the leftmost entry is
            // the original client. Trusted proxies are expected to strip
            // spoofed leftmost values.
            ProxyType::XForwardedFor => value.split(',').next()?.trim(),
            _ => value.trim(),
        };
        candidate.parse().ok()
    }
}

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
        default_value = "0.0.0.0:80",
        help = "A socket to listen for the server"
    )]
    listen: SocketAddr,

    #[arg(
        short,
        long,
        value_enum,
        default_value_t = ProxyType::XRealIp,
        help = "Which request header to trust for the client's real IP on the \
                index endpoint (also accepts `none` to ignore headers and use \
                the socket address)"
    )]
    proxy: ProxyType,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();
    tracing::event!(tracing::Level::INFO, "main");

    db::init_mmdb().await;
    db::init_country_cache().await;

    let routes = Router::new()
        .route("/", get(index))
        .route("/ip/{ip_address}", get(endpoint_get_ip))
        .route("/AS/{asn}", get(endpoint_get_asn))
        .route("/country/{country_code}", get(endpoint_get_country))
        .layer(Extension(args.proxy));

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
    use crate::db::init_mmdb;
    use crate::handlers::asn::endpoint_get_asn;
    use crate::handlers::country::endpoint_get_country;
    use crate::handlers::ip::{endpoint_get_ip, index};
    use crate::ProxyType;
    use axum::{
        Extension, Router,
        body::Body,
        extract::connect_info::MockConnectInfo,
        http::{self, Request, StatusCode},
        routing::get,
    };
    use std::net::SocketAddr;
    use tower::ServiceExt; // for `call`, `oneshot`, and `ready`

    #[tokio::test]
    async fn oncecell_not_none() {
        init_mmdb().await;
        crate::db::IPV4_ASN.get().unwrap();
        crate::db::IPV6_ASN.get().unwrap();
        crate::db::IPV4_COUNTRY.get().unwrap();
        crate::db::IPV6_COUNTRY.get().unwrap();
    }

    // The `index` handler reads the client IP from the header selected by the
    // `--proxy` flag (`X-Real-IP` by default) and falls back to the connected
    // socket address when that header is absent or malformed. See issues #29
    // and #38 for history.

    #[tokio::test]
    async fn index_header_x_real_ip_ipv4() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::XRealIp))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("X-Real-IP", "1.1.1.1")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn index_header_x_real_ip_ipv6() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::XRealIp))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("X-Real-IP", "2606:4700:4700::1111")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn index_no_header_fallback_ipv4() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "1.1.1.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::XRealIp))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn index_no_header_fallback_ipv6() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "[2606:4700:4700::1111]:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::XRealIp))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    // When `--proxy x-real-ip` (the default) is set, `CF-Connecting-IP` is
    // intentionally ignored by the `index` handler, which honors only the
    // selected header (and otherwise falls back to the socket address). These
    // tests confirm the header does not cause an error and is not required for
    // the request to succeed.

    #[tokio::test]
    async fn index_header_cfconnectingip_ip_ipv4() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "1.1.1.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::XRealIp))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("CF-Connecting-IP", "8.8.8.8")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn index_header_cfconnectingip_ip_ipv6() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "[2606:4700:4700::1111]:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::XRealIp))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("CF-Connecting-IP", "2001:4860:4860::8888")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    // When `--proxy cf-connecting-ip` is set, the `index` handler reads the
    // client IP from `CF-Connecting-IP` and falls back to the socket address
    // when that header is absent or malformed.

    #[tokio::test]
    async fn index_proxy_cf_connecting_ip_ipv4() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::CfConnectingIp))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("CF-Connecting-IP", "1.1.1.1")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn index_proxy_cf_connecting_ip_ipv6() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::CfConnectingIp))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("CF-Connecting-IP", "2606:4700:4700::1111")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    // When `--proxy x-forwarded-for` is set, the `index` handler reads the
    // leftmost entry of the comma-separated `X-Forwarded-For` list and falls
    // back to the socket address when the header is absent or malformed.

    #[tokio::test]
    async fn index_proxy_x_forwarded_for_single() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::XForwardedFor))
            .into_service::<Body>();
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
    async fn index_proxy_x_forwarded_for_multi() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::XForwardedFor))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("X-Forwarded-For", "1.1.1.1, 10.0.0.1, 192.168.1.1")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    // When `--proxy none` is set, the `index` handler ignores every header
    // and uses the connected socket address, even if a normally-trusted header
    // such as `X-Real-IP` is present.

    #[tokio::test]
    async fn index_proxy_none_ignores_headers() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "1.1.1.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::None))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("X-Real-IP", "8.8.8.8")
            .header("CF-Connecting-IP", "8.8.4.4")
            .header("X-Forwarded-For", "203.0.113.1")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
    }

    // A malformed value in the selected header must not panic the request
    // task; the handler falls back to the connected socket address instead.
    // This is the regression that motivates removing the previous `.unwrap()`
    // calls in the `index` handler.

    #[tokio::test]
    async fn index_proxy_malformed_header_falls_back() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "1.1.1.1:8000".parse::<SocketAddr>().unwrap(),
            ))
            .layer(Extension(ProxyType::XRealIp))
            .into_service::<Body>();
        let request = Request::builder()
            .method(http::Method::GET)
            .header("Accept", "*/*")
            .header("X-Real-IP", "not-an-ip")
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK)
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
        crate::db::init_country_cache().await;
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
