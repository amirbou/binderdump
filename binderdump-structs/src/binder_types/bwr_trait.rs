use super::super::errors::ToAnyhow;
use anyhow::Context;
use num;
use plain;

pub trait Bwr: Sized {
    type HeaderType: std::fmt::Debug + num::FromPrimitive;

    fn size(&self) -> usize;

    fn parse_with_header(header: &Self::HeaderType, data: &[u8]) -> Result<Self, plain::Error>;

    fn is_transaction(&self) -> bool;

    fn from_bytes(value: &[u8]) -> anyhow::Result<Self> {
        let header: &u32 =
            plain::from_bytes(value).map_err(|err| err.to_anyhow("Failed to read BR"))?;
        let header: Self::HeaderType = <Self::HeaderType as num::FromPrimitive>::from_u32(*header)
            .context("Failed to cast Header to enum")?;

        let data = &value[4..];
        Self::parse_with_header(&header, data)
            .map_err(|err| err.to_anyhow(&format!("Failed to read {:?}", header)))
    }
}
