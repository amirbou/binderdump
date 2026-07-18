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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_short_carries_msg_and_reason() {
        let err = plain::Error::TooShort.to_anyhow("reading header");
        assert_eq!(err.to_string(), "reading header - not enough data");
    }

    #[test]
    fn bad_alignment_carries_msg_and_reason() {
        let err = plain::Error::BadAlignment.to_anyhow("reading header");
        assert_eq!(err.to_string(), "reading header - bad alignment");
    }
}
