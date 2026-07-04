use crate::db::COUNTRY_CACHE;
use crate::handlers::PrettyJson;
use crate::models::CountryResponse;
use axum::{extract::Path, http::StatusCode};

pub async fn endpoint_get_country(
    Path(country_code): Path<String>,
) -> Result<PrettyJson<CountryResponse>, StatusCode> {
    if country_code.len() != 2 || !country_code.bytes().all(|c| matches!(c, b'A'..=b'Z')) {
        return Err(StatusCode::BAD_REQUEST);
    }

    match COUNTRY_CACHE.get().unwrap().get(&country_code) {
        Some(resp) => Ok(PrettyJson(resp.clone())),
        None => Err(StatusCode::BAD_REQUEST),
    }
}
