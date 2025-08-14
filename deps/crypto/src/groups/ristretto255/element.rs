use crate::groups::ristretto255::scalar::RistrettoScalar;
use crate::traits::element::GroupElement;
use crate::utils::rng;
use crate::utils::Error as CryptoError;
use core::fmt::Debug;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;

#[derive(Copy, Clone, Debug)]
pub struct RistrettoElement(pub RistrettoPoint);

impl RistrettoElement {
    pub fn new(point: RistrettoPoint) -> Self {
        RistrettoElement(point)
    }
}

impl GroupElement for RistrettoElement {
    type Scalar = RistrettoScalar;

    fn one() -> Self {
        RistrettoElement(RistrettoPoint::identity())
    }
    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        let ret = RistrettoPoint::random(rng);
        RistrettoElement(ret)
    }

    fn mul(&self, other: &Self) -> Self {
        RistrettoElement(self.0 + other.0)
    }

    fn inv(&self) -> Self {
        RistrettoElement(-self.0)
    }

    fn exp(&self, scalar: &Self::Scalar) -> Self {
        RistrettoElement(self.0 * scalar.0)
    }

    fn equals(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl PartialEq for RistrettoElement {
    fn eq(&self, other: &Self) -> bool {
        self.equals(other)
    }
}

use crate::utils::serialization::{VDeserializable, VSerializable};

impl VSerializable for RistrettoElement {
    fn ser(&self) -> Vec<u8> {
        let bytes = self.0.compress().to_bytes();
        bytes.to_vec()
    }
}

impl VDeserializable for RistrettoElement {
    fn deser(buffer: &[u8]) -> Result<Self, CryptoError> {
        let array = <[u8; 32]>::try_from(buffer).map_err(|_| {
            CryptoError::DeserializationError("Failed to convert Vec<u8> to [u8; 32]".to_string())
        })?;
        CompressedRistretto(array)
            .decompress()
            .map(RistrettoElement)
            .ok_or(CryptoError::DeserializationError(
                "Failed to parse Ristretto point bytes".to_string(),
            ))
    }
}

use crate::utils::serialization::{FDeserializable, FSerializable};
impl FSerializable for RistrettoElement {
    fn size_bytes() -> usize {
        32
    }
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let point = self.0.compress();
        let bytes = point.as_bytes();
        buffer.extend_from_slice(bytes);
    }
}
impl FDeserializable for RistrettoElement {
    fn deser_f(buffer: &[u8]) -> Result<Self, CryptoError> {
        Self::deser(buffer)
    }
}
