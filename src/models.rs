use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Asn {
    pub autonomous_system_number: usize,
    pub autonomous_system_organization: String,
    pub license: Option<String>,
    pub modifications: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Country {
    pub country_code: String,
}

#[derive(Serialize)]
pub struct RequestedAddress {
    pub ip: IpAddr,
    pub country: Option<Country>,
    pub asn: Option<Asn>,
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AsnResponse {
    pub asn: Asn,
    pub networks: Option<Vec<String>>,
}

impl AsnResponse {
    pub fn default(asn: Asn) -> Self {
        Self::new(asn, None)
    }

    pub fn new(asn: Asn, networks: Option<Vec<String>>) -> Self {
        AsnResponse { asn, networks }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CountryResponse {
    pub country: Country,
    pub networks: Option<Vec<String>>,
}
