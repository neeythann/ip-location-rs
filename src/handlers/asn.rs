use crate::db::ASN_CACHE;
use crate::handlers::PrettyJson;
use crate::models::AsnResponse;
use axum::{extract::Path, http::StatusCode};

// TODO(neeythann):
// - validate Path(asn)
pub async fn endpoint_get_asn(
    Path(asn): Path<usize>,
) -> Result<PrettyJson<AsnResponse>, StatusCode> {
    match ASN_CACHE.get().unwrap().get(&asn) {
        Some(resp) => Ok(PrettyJson(resp.clone())),
        None => Err(StatusCode::BAD_REQUEST),
    }
}
