use crate::traits::element::GroupElement;
use crate::traits::scalar::GroupScalar;
use crate::utils::Error;

use crate::utils::hash;
use crate::utils::rng;

pub trait CryptoGroup {
    type Element: GroupElement<Scalar = Self::Scalar>;
    type Scalar: GroupScalar;
    type Hasher: hash::Hasher;
    type Plaintext;
    type Message;

    fn generator() -> Self::Element;

    fn hash_to_scalar(input_slices: &[&[u8]], ds_tags: &[&[u8]]) -> Self::Scalar;

    fn random_element<R: rng::CRng>(rng: &mut R) -> Self::Element;
    fn random_scalar<R: rng::CRng>(rng: &mut R) -> Self::Scalar;

    fn encode(p: &Self::Plaintext) -> Result<Self::Message, Error>;
    fn decode(p: &Self::Message) -> Result<Self::Plaintext, Error>;

    fn ind_generators(count: usize, label: &[u8]) -> Vec<Self::Element>;
}
