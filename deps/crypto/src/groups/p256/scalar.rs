use crate::traits::scalar::GroupScalar;
use crate::utils::rng;
use crate::utils::Error as CryptoError;
use core::fmt::Debug;
use p256::elliptic_curve::Field;
use p256::Scalar;
use p256::Scalar as P256CrateScalar;
use std::ops::Neg;

#[derive(Debug, Clone, Copy)]
pub struct P256Scalar(pub Scalar);

impl P256Scalar {
    pub fn new(scalar: Scalar) -> Self {
        P256Scalar(scalar)
    }
}

impl GroupScalar for P256Scalar {
    fn zero() -> Self {
        P256Scalar(Scalar::ZERO)
    }

    fn one() -> Self {
        P256Scalar(Scalar::ONE)
    }

    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        let scalar = P256CrateScalar::random(rng);
        P256Scalar::new(scalar)
    }

    fn add(&self, other: &Self) -> Self {
        P256Scalar(self.0 + other.0)
    }

    fn sub(&self, other: &Self) -> Self {
        P256Scalar(self.0 - other.0)
    }

    fn mul(&self, other: &Self) -> Self {
        P256Scalar(self.0 * other.0)
    }

    fn neg(&self) -> Self {
        P256Scalar(self.0.neg())
    }

    fn inv(&self) -> Option<Self> {
        // p256::Scalar::invert returns a CtOption<Scalar>
        let inverted = self.0.invert();
        if inverted.is_some().unwrap_u8() == 1 {
            Some(P256Scalar(inverted.unwrap()))
        } else {
            None
        }
    }

    fn equals(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<u32> for P256Scalar {
    fn from(u: u32) -> P256Scalar {
        let scalar: P256CrateScalar = u.into();

        P256Scalar(scalar)
    }
}

impl PartialEq for P256Scalar {
    fn eq(&self, other: &Self) -> bool {
        GroupScalar::equals(self, other)
    }
}

use crate::utils::serialization::{VDeserializable, VSerializable};
use p256::elliptic_curve::PrimeField;

impl VSerializable for P256Scalar {
    fn ser(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();
        bytes.to_vec()
    }
}

impl VDeserializable for P256Scalar {
    fn deser(buffer: &[u8]) -> Result<Self, CryptoError> {
        let bytes = <[u8; 32]>::try_from(buffer).map_err(|_| {
            CryptoError::DeserializationError("Failed to convert Vec<u8> to [u8; 32]".to_string())
        })?;

        let scalar = Scalar::from_repr(bytes.into()).map(P256Scalar);

        if scalar.is_some().into() {
            Ok(scalar.expect("impossible"))
        } else {
            Err(CryptoError::DeserializationError(
                "Failed to parse P256 scalar bytes".to_string(),
            ))
        }
    }
}

use crate::utils::serialization::{FDeserializable, FSerializable};
impl FSerializable for P256Scalar {
    fn size_bytes() -> usize {
        32
    }
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let bytes = self.0.to_bytes();
        buffer.extend(bytes);
    }
}
impl FDeserializable for P256Scalar {
    fn deser_f(buffer: &[u8]) -> Result<Self, CryptoError> {
        Self::deser(buffer)
    }
}
