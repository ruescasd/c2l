pub mod element;
pub mod scalar;

pub use element::RistrettoElement;
pub use scalar::RistrettoScalar;

use crate::traits::group::CryptoGroup;

use crate::traits::element::GroupElement;
use crate::traits::scalar::GroupScalar;
use crate::utils::hash;
use crate::utils::hash::Hasher;
use crate::utils::rng;
use crate::utils::Error;

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::{constants as dalek_constants, RistrettoPoint};
use sha3::Digest;

use rayon::prelude::*;

#[derive(Debug, Clone)]
pub struct Ristretto255Group;

impl CryptoGroup for Ristretto255Group {
    type Element = RistrettoElement;
    type Scalar = RistrettoScalar;
    type Hasher = hash::Hasher512;
    type Plaintext = [u8; 30];
    type Message = Self::Element;

    fn generator() -> Self::Element {
        RistrettoElement::new(dalek_constants::RISTRETTO_BASEPOINT_POINT)
    }

    fn hash_to_scalar(input_slices: &[&[u8]], ds_tags: &[&[u8]]) -> Self::Scalar {
        let mut hasher = Self::Hasher::hasher();
        hash::update_hasher(&mut hasher, input_slices, ds_tags);

        RistrettoScalar::from_hash::<Self::Hasher>(hasher)
    }

    #[inline(always)]
    fn random_element<R: rng::CRng>(rng: &mut R) -> Self::Element {
        Self::Element::random(rng)
    }

    #[inline(always)]
    fn random_scalar<R: rng::CRng>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::random(rng)
    }

    // see https://github.com/dalek-cryptography/curve25519-dalek/issues/322
    // see https://github.com/hdevalence/ristretto255-data-encoding/blob/master/src/main.rs
    fn encode(input: &Self::Plaintext) -> Result<Self::Message, Error> {
        let mut bytes = [0u8; 32];
        bytes[1..1 + input.len()].copy_from_slice(input);
        for j in 0..64 {
            bytes[31] = j as u8;
            for i in 0..128 {
                bytes[0] = 2 * i as u8;
                if let Some(point) = CompressedRistretto(bytes).decompress() {
                    return Ok(RistrettoElement(point));
                }
            }
        }
        Err(Error::EncodingError(
            "Failed to encode into ristretto point".to_string(),
        ))
    }

    fn decode(message: &Self::Message) -> Result<Self::Plaintext, Error> {
        let compressed = message.0.compress();
        // the 30 bytes of data are placed in the range 1-30
        let slice = &compressed.as_bytes()[1..31];
        let ret: Self::Plaintext = slice
            .try_into()
            .expect("impossible, passed slice is size 30");

        Ok(ret)
    }

    fn ind_generators(count: usize, label: &[u8]) -> Vec<Self::Element> {
        let mut hasher = Self::Hasher::hasher();
        hasher.update(label);
        hasher.update(b"independent_generators_ristretto");

        #[crate::warning("The following code is not optimized. Parallelize with rayon")]
        let ret: Vec<RistrettoElement> = (0..count)
            .into_par_iter()
            .map(|i| {
                let mut hasher = hasher.clone();
                hasher.update(i.to_be_bytes());
                let point = RistrettoPoint::from_hash(hasher);
                RistrettoElement(point)
            })
            .collect();

        ret
    }
}

#[cfg(test)]
mod tests;
