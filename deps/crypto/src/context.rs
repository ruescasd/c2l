use rand::rngs::OsRng;

use crate::groups::P256Group;
use crate::groups::Ristretto255Group;
use crate::traits::group::CryptoGroup;
use crate::traits::GroupElement;
use crate::traits::GroupScalar;
use crate::utils::hash::Hasher;
use crate::utils::rng::Rng;
use crate::utils::serialization::{FSer, VSer};
use crate::utils::signatures::Ed25519;
use crate::utils::signatures::Signatures;

pub trait Context: private::Sealed + std::fmt::Debug + PartialEq + 'static + Clone {
    type Element: GroupElement<Scalar = Self::Scalar> + FSer + VSer + Clone + Send + Sync + Eq;
    type Scalar: GroupScalar + FSer + VSer + Clone + Send + Sync + From<u32>;
    type Hasher: Hasher;
    type R: Rng;
    type Signatures: Signatures<Self::R>;

    type G: CryptoGroup<Element = Self::Element, Scalar = Self::Scalar, Hasher = Self::Hasher>;

    #[inline(always)]
    fn get_rng() -> Self::R {
        Self::R::rng()
    }

    #[inline(always)]
    fn get_hasher() -> Self::Hasher {
        Self::Hasher::hasher()
    }

    #[inline(always)]
    fn random_element() -> Self::Element {
        let mut rng = Self::get_rng();
        Self::G::random_element(&mut rng)
    }

    #[inline(always)]
    fn random_scalar() -> Self::Scalar {
        let mut rng = Self::get_rng();
        Self::G::random_scalar(&mut rng)
    }

    #[inline(always)]
    fn generator() -> Self::Element {
        Self::G::generator()
    }

    fn get_name() -> String;
}

#[derive(Debug, PartialEq, Clone)]
pub struct P256Ctx;
impl Context for P256Ctx {
    type Element = <Self::G as CryptoGroup>::Element;
    type Scalar = <Self::G as CryptoGroup>::Scalar;
    type Hasher = <Self::G as CryptoGroup>::Hasher;
    type R = OsRng;
    type Signatures = Ed25519<Self::R>;

    type G = P256Group;

    fn get_name() -> String { "P256Ctx".into() }
}
#[derive(Debug, PartialEq, Clone, Eq)]
pub struct RistrettoCtx;
impl Context for RistrettoCtx {
    type Element = <Self::G as CryptoGroup>::Element;
    type Scalar = <Self::G as CryptoGroup>::Scalar;
    type Hasher = <Self::G as CryptoGroup>::Hasher;
    type R = OsRng;
    type Signatures = Ed25519<Self::R>;

    type G = Ristretto255Group;

    fn get_name() -> String { "RistrettoCtx".into() }
}

mod private {
    pub trait Sealed {}
}
impl private::Sealed for RistrettoCtx {}
impl private::Sealed for P256Ctx {}
