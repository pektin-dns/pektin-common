use std::convert::TryInto;

use pektin_common::{CertUsage, Matching, Property, RecordData, Selector};
use serde_json;
use trust_dns_proto::rr::RData;

fn main() -> Result<(), String> {
    let caa = RecordData::CAA {
        issuer_critical: false,
        tag: Property::Iodef,
        value: "http://deine.mutter".into(),
    };
    let openpgpkey = RecordData::OPENPGPKEY("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".into());
    let tlsa = RecordData::TLSA {
        cert_usage: CertUsage::DomainIssued,
        selector: Selector::Spki,
        matching: Matching::Sha256,
        cert_data: "872ec9adeacaafd8067747bb97d1a27f11052d5250126a1057f403d68a52b316".into(),
    };
    let txt = RecordData::TXT("v=spf1".into());

    println!("{}", serde_json::to_string_pretty(&caa).unwrap());
    println!("{}", serde_json::to_string_pretty(&openpgpkey).unwrap());
    println!("{}", serde_json::to_string_pretty(&tlsa).unwrap());
    println!("{}", serde_json::to_string_pretty(&txt).unwrap());

    let _: RData = caa.try_into()?;
    let _: RData = openpgpkey.try_into()?;
    let _: RData = tlsa.try_into()?;
    let _: RData = txt.try_into()?;

    Ok(())
}
