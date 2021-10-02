pub use trust_dns_proto as proto;

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

pub fn load_env(default: &str, param_name: &str, log: bool) -> Result<String, PektinCommonError> {
    let res = if let Ok(param) = env::var(param_name) {
        param
    } else {
        if default.is_empty() {
            return Err(PektinCommonError::MissingEnvVar(param_name.into()));
        } else {
            default.into()
        }
    };
    if log {
        println!("\t{}={}", param_name, res);
    }
    Ok(res)
}
