use axum::response::{IntoResponse, Response};
use serde::Serialize;

pub mod asn;
pub mod country;
pub mod ip;

pub struct PrettyJson<T>(pub T);

impl<T: Serialize> IntoResponse for PrettyJson<T> {
    fn into_response(self) -> Response {
        let body = serde_json::to_string_pretty(&self.0).expect("failed to serialize response");
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response()
    }
}
