use crate::models::{Asn, Country};
use maxminddb::Reader;
use std::{fmt::Error, net::IpAddr};
use tokio::sync::OnceCell;

pub static IPV4_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
pub static IPV4_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

pub static IPV6_COUNTRY: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();
pub static IPV6_ASN: OnceCell<Reader<Vec<u8>>> = OnceCell::const_new();

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
    match reader
        .lookup(ip)
        .expect("Invalid IP address!")
        .decode::<Asn>()
        .unwrap()
    {
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
