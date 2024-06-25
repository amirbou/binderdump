use std::num::TryFromIntError;

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
    #[error("New struct encountered after offsets processing was finished!")]
    TooManyStructs,
    #[error("No struct in stack!")]
    EmptyStructStack,
    #[error("No fields in stack")]
    EmptyFieldsStack,
    #[error("Too many fields encountred for struct")]
    TooManyFields,
    #[error("Not enough fields")]
    TooLittleFields,
    #[error("No fields in previous struct!")]
    NoFields,
    #[error("Previous field already has an inner_struct!")]
    DoubleInnerStruct,
    #[error("Struct stack non-empty")]
    UnexpectedStruct,
    #[error("Fields stack non-empty")]
    UnexpectedFields,
    #[error("No result produced")]
    NoResult,
    #[error("Sequence field length is too big {0}")]
    TooBig(TryFromIntError),
    #[error("Unknown length for sequence")]
    UnknownLength,
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
