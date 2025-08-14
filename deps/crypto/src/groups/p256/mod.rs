pub mod element;
pub mod scalar;

pub use element::P256Element;
pub use scalar::P256Scalar;

use crate::traits::group::CryptoGroup;
use crate::utils::rng;
use crate::utils::Error;

use crate::traits::element::GroupElement;
use crate::traits::scalar::GroupScalar;
use p256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
use p256::NistP256;
use p256::ProjectivePoint;

use crate::utils::hash;

#[derive(Debug, Clone)]
pub struct P256Group;

impl CryptoGroup for P256Group {
    type Element = P256Element;
    type Scalar = P256Scalar;
    type Hasher = hash::Hasher256;
    type Plaintext = [u8; 30];
    type Message = Self::Element;

    fn generator() -> Self::Element {
        P256Element::new(ProjectivePoint::GENERATOR)
    }

    fn hash_to_scalar(input_slices: &[&[u8]], ds_tags: &[&[u8]]) -> Self::Scalar {
        let ret = NistP256::hash_to_scalar::<ExpandMsgXmd<Self::Hasher>>(input_slices, ds_tags);

        #[crate::warning("Fix this unwrap, modify hash_to_scalar trait to return result")]
        P256Scalar(ret.unwrap())
    }

    fn random_element<R: rng::CRng>(rng: &mut R) -> Self::Element {
        Self::Element::random(rng)
    }

    fn random_scalar<R: rng::CRng>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::random(rng)
    }

    fn encode(_p: &Self::Plaintext) -> Result<Self::Message, Error> {
        todo!()
    }
    fn decode(_p: &Self::Message) -> Result<Self::Plaintext, Error> {
        todo!()
    }

    fn ind_generators(count: usize, label: &[u8]) -> Vec<Self::Element> {
        let ds_tags: &[&[u8]] = &[b"context", b"independent_generators_p256_counter"];
        let mut ret = vec![];

        #[crate::warning("The following code is not optimized. Parallelize with rayon")]
        for i in 0..count {
            let inputs = &[label, &i.to_be_bytes()];
            let point = NistP256::hash_from_bytes::<ExpandMsgXmd<Self::Hasher>>(inputs, ds_tags);
            let point = point.unwrap();
            ret.push(P256Element(point));
        }

        ret
    }
}

#[cfg(test)]
mod tests;
