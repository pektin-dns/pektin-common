pub use deadpool_redis;
use proto::rr::{
    rdata::{caa, openpgpkey, tlsa, txt, CAA, MX, SOA, SRV},
    Name,
};
pub use trust_dns_proto as proto;

use deadpool_redis::redis::AsyncCommands;
use deadpool_redis::Connection;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{
    convert::{TryFrom, TryInto},
    env,
    net::{Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PektinCommonError {
    #[error("Environment variable {0} is required, but not set")]
    MissingEnvVar(String),
    #[error("Environment variable {0} is invalid")]
    InvalidEnvVar(String),
    #[error("Error contacting Redis")]
    Redis(#[from] deadpool_redis::redis::RedisError),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ResourceRecord {
    pub ttl: u32,
    pub value: RecordData,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RedisEntry {
    pub name: String,
    pub rr_set: Vec<ResourceRecord>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Property {
    #[serde(rename = "iodef")]
    Iodef,
    #[serde(rename = "issue")]
    Issue,
    #[serde(rename = "issuewild")]
    IssueWild,
}

impl From<Property> for caa::Property {
    fn from(prop: Property) -> Self {
        match prop {
            Property::Iodef => caa::Property::Iodef,
            Property::Issue => caa::Property::Issue,
            Property::IssueWild => caa::Property::IssueWild,
        }
    }
}

#[derive(Clone, Debug, Deserialize_repr, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum CertUsage {
    CA = 0,
    Service = 1,
    TrustAnchor = 2,
    DomainIssued = 3,
}

impl From<CertUsage> for tlsa::CertUsage {
    fn from(usage: CertUsage) -> Self {
        match usage {
            CertUsage::CA => Self::CA,
            CertUsage::Service => Self::Service,
            CertUsage::TrustAnchor => Self::TrustAnchor,
            CertUsage::DomainIssued => Self::DomainIssued,
        }
    }
}

#[derive(Clone, Debug, Deserialize_repr, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum Selector {
    Full = 0,
    Spki = 1,
}

impl From<Selector> for tlsa::Selector {
    fn from(selector: Selector) -> Self {
        match selector {
            Selector::Full => Self::Full,
            Selector::Spki => Self::Spki,
        }
    }
}

#[derive(Clone, Debug, Deserialize_repr, PartialEq, Serialize_repr)]
#[repr(u8)]
pub enum Matching {
    Raw = 0,
    Sha256 = 1,
    Sha512 = 2,
}

impl From<Matching> for tlsa::Matching {
    fn from(matching: Matching) -> Self {
        match matching {
            Matching::Raw => Self::Raw,
            Matching::Sha256 => Self::Sha256,
            Matching::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum RecordData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CAA {
        issuer_critical: bool,
        tag: Property,
        value: String,
    },
    CNAME(Name),
    MX(MX),
    NS(Name),
    OPENPGPKEY(String),
    SOA(SOA),
    SRV(SRV),
    TLSA {
        cert_usage: CertUsage,
        selector: Selector,
        matching: Matching,
        cert_data: String,
    },
    TXT(String),
}

impl RecordData {
    pub fn convert(self) -> Result<trust_dns_proto::rr::RData, String> {
        self.try_into()
    }
}

impl TryFrom<RecordData> for trust_dns_proto::rr::RData {
    type Error = String;
    fn try_from(rec: RecordData) -> Result<Self, String> {
        match rec {
            RecordData::A(addr) => Ok(Self::A(addr)),
            RecordData::AAAA(addr) => Ok(Self::AAAA(addr)),
            RecordData::CAA {
                issuer_critical,
                tag,
                value,
            } => {
                let value = match tag {
                    Property::Iodef => {
                        caa::Value::Url(url::Url::parse(&value).map_err(|e| e.to_string())?)
                    }
                    Property::Issue => caa::Value::Issuer(
                        Some(Name::from_utf8(value).map_err(|e| e.to_string())?),
                        vec![],
                    ),
                    Property::IssueWild => caa::Value::Issuer(
                        Some(Name::from_utf8(value).map_err(|e| e.to_string())?),
                        vec![],
                    ),
                };
                Ok(Self::CAA(CAA {
                    issuer_critical,
                    tag: tag.into(),
                    value,
                }))
            }
            RecordData::CNAME(name) => Ok(Self::CNAME(name)),
            RecordData::MX(mx) => Ok(Self::MX(mx)),
            RecordData::NS(name) => Ok(Self::NS(name)),
            RecordData::OPENPGPKEY(key) => Ok(Self::OPENPGPKEY(openpgpkey::OPENPGPKEY::new(
                base64::decode(&key).map_err(|e| e.to_string())?,
            ))),
            RecordData::SOA(soa) => Ok(Self::SOA(soa)),
            RecordData::SRV(srv) => Ok(Self::SRV(srv)),
            RecordData::TLSA {
                cert_usage,
                selector,
                matching,
                cert_data,
            } => Ok(Self::TLSA(tlsa::TLSA::new(
                cert_usage.into(),
                selector.into(),
                matching.into(),
                hex::decode(&cert_data).map_err(|e| e.to_string())?,
            ))),
            RecordData::TXT(txt) => Ok(Self::TXT(txt::TXT::new(vec![txt]))),
        }
    }
}

pub fn load_env(
    default: &str,
    param_name: &str,
    confidential: bool,
) -> Result<String, PektinCommonError> {
    let res = if let Ok(param) = env::var(param_name) {
        param
    } else {
        if default.is_empty() {
            return Err(PektinCommonError::MissingEnvVar(param_name.into()));
        } else {
            default.into()
        }
    };
    if !confidential {
        println!("\t{}={}", param_name, res);
    } else {
        println!("\t{}=<REDACTED>", param_name);
    }
    Ok(res)
}

// find all zones that we are authoritative for
pub async fn get_authoritative_zones(
    con: &mut Connection,
) -> Result<Vec<String>, PektinCommonError> {
    Ok(con
        .keys::<_, Vec<String>>("*.:SOA")
        .await?
        .into_iter()
        .map(|mut key| {
            key.truncate(key.find(":").unwrap());
            key
        })
        .collect())
}
