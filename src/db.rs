use crate::models::{Asn, Country, CountryResponse, Notes};
use maxminddb::Reader;
use std::{collections::HashMap, fmt::Error, net::IpAddr};
use tokio::sync::OnceCell;

/// Attribution metadata for the underlying MMDB data sources. Returned on every
/// API response so consumers always see the same `notes` shape regardless of
/// endpoint or whether the `asn` field is populated.
pub fn notes() -> Notes {
    Notes {
        license: Some(String::from("CC BY 4.0 by RouteViews and DB-IP")),
        modifications: Some(String::from(
            "https://github.com/sapics/ip-location-db/blob/main/asn/MODIFICATIONS",
        )),
    }
}

pub static IPV4_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
pub static IPV4_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

pub static IPV6_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
pub static IPV6_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

pub static COUNTRY_CACHE: OnceCell<HashMap<String, CountryResponse>> = OnceCell::const_new();

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
    reader
        .lookup(ip)
        .expect("Invalid IP address!")
        .decode::<Country>()
        .unwrap()
}

pub fn get_asn(ip: IpAddr) -> Option<Asn> {
    let reader = match ip {
        IpAddr::V4(_) => IPV4_ASN.get().unwrap(),
        IpAddr::V6(_) => IPV6_ASN.get().unwrap(),
    };
    reader
        .lookup(ip)
        .expect("Invalid IP address!")
        .decode::<Asn>()
        .unwrap()
}

pub async fn init_mmdb() {
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

pub async fn init_country_cache() {
    COUNTRY_CACHE
        .get_or_init(|| async {
            let mut cache: HashMap<String, CountryResponse> = HashMap::new();

            let network4: ipnetwork::IpNetwork = "0.0.0.0/0".parse().unwrap();
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
                let network = lookup.network().unwrap().to_string();
                cache
                    .entry(country_data.country_code.clone())
                    .and_modify(|resp| {
                        if let Some(nets) = resp.networks.as_mut() {
                            nets.push(network.clone());
                        }
                    })
                    .or_insert_with(|| CountryResponse {
                        country: country_data,
                        networks: Some(vec![network]),
                        notes: notes(),
                    });
            }

            let network6: ipnetwork::IpNetwork = "::0/0".parse().unwrap();
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
                let network = lookup.network().unwrap().to_string();
                cache
                    .entry(country_data.country_code.clone())
                    .and_modify(|resp| {
                        if let Some(nets) = resp.networks.as_mut() {
                            nets.push(network.clone());
                        }
                    })
                    .or_insert_with(|| CountryResponse {
                        country: country_data,
                        networks: Some(vec![network]),
                        notes: notes(),
                    });
            }

            cache
        })
        .await;
}
