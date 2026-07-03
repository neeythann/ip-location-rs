pub mod db;
pub mod handlers;
pub mod models;

use axum::{Router, routing::get};
use clap::Parser;
use handlers::{
    asn::endpoint_get_asn,
    country::endpoint_get_country,
    ip::{endpoint_get_ip, index},
};
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    use crate::db::init_mmdb;
    use crate::handlers::asn::endpoint_get_asn;
    use crate::handlers::country::endpoint_get_country;
    use crate::handlers::ip::{endpoint_get_ip, index};
    use axum::{
        Router,
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

    // The `index` handler favors the `X-Real-IP` header and falls back to the
    // connected socket address when it is absent. See issue #29 for history.

    #[tokio::test]
    async fn index_header_x_real_ip_ipv4() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "127.0.0.1:8000".parse::<SocketAddr>().unwrap(),
            ))
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

    // `CF-Connecting-IP` is intentionally ignored by the `index` handler,
    // which only honors `X-Real-IP` (and otherwise falls back to the socket
    // address). These tests confirm the header does not cause an error and
    // is not required for the request to succeed.

    #[tokio::test]
    async fn index_header_cfconnectingip_ip_ipv4() {
        init_mmdb().await;
        let app = Router::new()
            .route("/", get(index))
            .layer(MockConnectInfo(
                "1.1.1.1:8000".parse::<SocketAddr>().unwrap(),
            ))
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
