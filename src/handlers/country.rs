use crate::db::{IPV4_COUNTRY, IPV6_COUNTRY};
use crate::models::{Country, CountryResponse};
use axum::{Json, extract::Path, http::StatusCode};
use ipnetwork::IpNetwork;
use tokio::task::yield_now;

// TODO(neeythann):
// - validate Path(country) with ISO 3166-1 alpha-2
// - cache this result at startup
pub async fn endpoint_get_country(
    Path(country_code): Path<String>,
) -> Result<Json<CountryResponse>, StatusCode> {
    if country_code.len() != 2 || !country_code.bytes().all(|c| matches!(c, b'A'..=b'Z')) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut net: Vec<String> = vec![];
    let mut country_info: Option<Country> = None;

    let network4: IpNetwork = "0.0.0.0/0".parse().unwrap();
    let mut iter = IPV4_COUNTRY
        .get()
        .unwrap()
        .within(network4, Default::default())
        .unwrap();
    while let Some(next) = iter.next() {
        let lookup = next.unwrap();
        let country_data: Country = match lookup.decode() {
            Ok(Some(data)) => data,
            _ => continue,
        };
        if country_data.country_code != country_code {
            continue;
        }

        if country_info.is_none() {
            country_info = Some(country_data);
        }
        net.push(lookup.network().unwrap().to_string());
        yield_now().await;
    }

    let network6: IpNetwork = "::0/0".parse().unwrap();
    iter = IPV6_COUNTRY
        .get()
        .unwrap()
        .within(network6, Default::default())
        .unwrap();
    while let Some(next) = iter.next() {
        let lookup = next.unwrap();
        let country_data: Country = match lookup.decode() {
            Ok(Some(data)) => data,
            _ => continue,
        };
        if country_data.country_code != country_code {
            continue;
        }
        net.push(lookup.network().unwrap().to_string());
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
