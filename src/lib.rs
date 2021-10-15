pub use deadpool_redis;
pub use trust_dns_proto as proto;

use deadpool_redis::redis::AsyncCommands;
use deadpool_redis::Connection;
use serde::{Deserialize, Serialize};
use std::env;
use thiserror::Error;
use trust_dns_proto::rr::RData;

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
    pub value: RData,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RedisEntry {
    pub name: String,
    pub rr_set: Vec<ResourceRecord>,
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
