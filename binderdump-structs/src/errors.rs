use anyhow::{anyhow, Error};
use plain;

pub trait ToAnyhow {
    fn to_anyhow(&self, msg: &str) -> Error;
}

impl ToAnyhow for plain::Error {
    fn to_anyhow(&self, msg: &str) -> Error {
        match self {
            plain::Error::TooShort => anyhow!("{} - not enough data", msg),
            plain::Error::BadAlignment => anyhow!("{} - bad alignment", msg),
        }
    }
}
