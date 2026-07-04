use crate::db::{IPV4_ASN, IPV6_ASN};
use crate::handlers::PrettyJson;
use crate::models::{Asn, AsnResponse};
use axum::{extract::Path, http::StatusCode};
use ipnetwork::IpNetwork;
use tokio::task::yield_now;

// TODO(neeythann):
// - validate Path(asn)
// - cache this result at startup
pub async fn endpoint_get_asn(
    Path(asn): Path<usize>,
) -> Result<PrettyJson<AsnResponse>, StatusCode> {
    let network4: IpNetwork = "0.0.0.0/0".parse().unwrap();
    let network6: IpNetwork = "::0/0".parse().unwrap();
    let mut net: Vec<String> = vec![];

    let mut asn_info: Option<Asn> = None;

    let mut iter = IPV4_ASN
        .get()
        .unwrap()
        .within(network4, Default::default())
        .unwrap();
    while let Some(next) = iter.next() {
        let lookup = next.unwrap();
        let asn_data: Asn = match lookup.decode() {
            Ok(Some(data)) => data,
            _ => continue,
        };
        if asn_data.autonomous_system_number != asn {
            continue;
        }

        if asn_info.is_none() {
            asn_info = Some(asn_data.clone());
        }
        net.push(lookup.network().unwrap().to_string());
        yield_now().await;
    }
    iter = IPV6_ASN
        .get()
        .unwrap()
        .within(network6, Default::default())
        .unwrap();
    while let Some(next) = iter.next() {
        let lookup = next.unwrap();
        let asn_data: Asn = match lookup.decode() {
            Ok(Some(data)) => data,
            _ => continue,
        };
        if asn_data.autonomous_system_number != asn {
            continue;
        }
        net.push(lookup.network().unwrap().to_string());
        yield_now().await;
    }

    if asn_info.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(PrettyJson(AsnResponse::new(asn_info.unwrap(), Some(net))))
}
