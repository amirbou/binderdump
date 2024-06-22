use serde::{de, ser};
use thiserror;

#[derive(thiserror::Error, Debug)]
pub enum PlainSerializerError {
    #[error("Serialize not implemented for type `{0}`")]
    SerNotImplmented(&'static str),
    #[error("Deserialize not implemented for type `{0}`")]
    DeNotImplmented(&'static str),
    #[error("Error: {0}")]
    Custom(String),
    #[error("IO Error: {0}")]
    IoError(std::io::Error),
    #[error("String parsing error: {0}")]
    Utf8Error(std::str::Utf8Error),
}

impl From<std::io::Error> for PlainSerializerError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

impl ser::Error for PlainSerializerError {
    fn custom<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Custom(msg.to_string())
    }
}

impl de::Error for PlainSerializerError {
    fn custom<T>(msg: T) -> Self
    where
        T: std::fmt::Display,
    {
        Self::Custom(msg.to_string())
    }
}