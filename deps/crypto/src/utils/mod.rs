pub mod hash;
pub mod rng;
pub mod serialization;
pub mod signatures;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    DeserializationError(String),
    #[error("{0}")]
    SerializationError(String),
    #[error("{0}")]
    Custom(String),
    #[error("Try from slice error: {0}")]
    SliceError(#[from] std::array::TryFromSliceError),
    #[error("{0}")]
    EncodingError(String),
    #[error("{0}")]
    SignatureError(#[from] ed25519_dalek::ed25519::Error),
    #[error("{0}")]
    NaorYungStripError(String),
    #[error("{0}")]
    InvalidThreshold(String),
}
