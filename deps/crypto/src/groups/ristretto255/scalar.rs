use crate::traits::scalar::GroupScalar;
use crate::utils::rng;
use crate::utils::Error as CryptoError;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use sha3::digest::typenum::U64;
use sha3::digest::Digest;

#[derive(Copy, Clone, Debug)]
pub struct RistrettoScalar(pub DalekScalar);

impl RistrettoScalar {
    pub fn new(scalar: DalekScalar) -> Self {
        RistrettoScalar(scalar)
    }

    pub fn from_hash<D: Digest<OutputSize = U64>>(hasher: D) -> Self {
        RistrettoScalar(DalekScalar::from_hash::<D>(hasher))
    }
}

impl GroupScalar for RistrettoScalar {
    fn zero() -> Self {
        RistrettoScalar(DalekScalar::ZERO)
    }
    fn one() -> Self {
        RistrettoScalar(DalekScalar::ONE)
    }
    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        let ret = DalekScalar::random(rng);
        RistrettoScalar(ret)
    }

    fn add(&self, other: &Self) -> Self {
        RistrettoScalar(self.0 + other.0)
    }

    fn sub(&self, other: &Self) -> Self {
        RistrettoScalar(self.0 - other.0)
    }

    fn mul(&self, other: &Self) -> Self {
        RistrettoScalar(self.0 * other.0)
    }

    fn neg(&self) -> Self {
        RistrettoScalar(-self.0)
    }

    fn inv(&self) -> Option<Self> {
        if self.0 == DalekScalar::ZERO {
            None
        } else {
            Some(RistrettoScalar(self.0.invert()))
        }
    }

    fn equals(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl From<u32> for RistrettoScalar {
    fn from(u: u32) -> RistrettoScalar {
        let scalar: DalekScalar = u.into();

        RistrettoScalar(scalar)
    }
}

impl PartialEq for RistrettoScalar {
    fn eq(&self, other: &Self) -> bool {
        GroupScalar::equals(self, other)
    }
}

use crate::utils::serialization::{VDeserializable, VSerializable};

impl VSerializable for RistrettoScalar {
    fn ser(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();
        bytes.to_vec()
    }
}

impl VDeserializable for RistrettoScalar {
    fn deser(buffer: &[u8]) -> Result<Self, CryptoError> {
        let bytes = <[u8; 32]>::try_from(buffer).map_err(|_| {
            CryptoError::DeserializationError("Failed to convert Vec<u8> to [u8; 32]".to_string())
        })?;
        let opt: Option<RistrettoScalar> = DalekScalar::from_canonical_bytes(bytes)
            .map(RistrettoScalar)
            .into();
        opt.ok_or(CryptoError::DeserializationError(
            "Failed to convert parse Ristretto scalar bytes".to_string(),
        ))
    }
}

use crate::utils::serialization::{FDeserializable, FSerializable};
impl FSerializable for RistrettoScalar {
    fn size_bytes() -> usize {
        32
    }
    fn ser_into(&self, buffer: &mut Vec<u8>) {
        let bytes = self.0.as_bytes();
        buffer.extend_from_slice(bytes);
    }
}
impl FDeserializable for RistrettoScalar {
    fn deser_f(buffer: &[u8]) -> Result<Self, CryptoError> {
        Self::deser(buffer)
    }
}
