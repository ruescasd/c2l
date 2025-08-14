use crate::traits::scalar::GroupScalar;
use crate::utils::rng;
use std::array;
use std::fmt::Debug;

pub trait GroupElement: Sized + Debug + PartialEq {
    type Scalar: GroupScalar;

    fn one() -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn inv(&self) -> Self;
    fn exp(&self, scalar: &Self::Scalar) -> Self;
    fn equals(&self, other: &Self) -> bool;

    fn random<R: rng::CRng>(rng: &mut R) -> Self;
}

impl<T: GroupElement, const N: usize> GroupElement for [T; N] {
    type Scalar = [T::Scalar; N];

    fn one() -> Self {
        array::from_fn(|_| T::one())
    }
    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        array::from_fn(|_| T::random(rng))
    }

    fn mul(&self, other: &Self) -> Self {
        array::from_fn(|i| self[i].mul(&other[i]))
    }
    fn inv(&self) -> Self {
        array::from_fn(|i| self[i].inv())
    }

    fn exp(&self, other: &Self::Scalar) -> Self {
        array::from_fn(|i| self[i].exp(&other[i]))
    }

    fn equals(&self, other: &Self) -> bool {
        for (i, item) in self.iter().enumerate() {
            let other: &T = &other[i];
            if !item.equals(other) {
                return false;
            }
        }
        true
    }
}

pub trait Widen<Rhs: GroupElement>: GroupElement {
    type Output;

    fn widen_mul(&self, other: &Rhs) -> Self::Output;
    fn widen_exp(&self, other: &Rhs::Scalar) -> Self::Output;
    fn widen_equals(&self, other: &Rhs) -> bool;
}

pub trait Narrow<Rhs: GroupElement>: GroupElement {
    type Output;

    fn narrow_mul(&self, other: &Rhs) -> Self::Output;
    fn narrow_exp(&self, other: &Rhs::Scalar) -> Self::Output;
    fn narrow_equals(&self, other: &Rhs) -> bool;
}

impl<T: GroupElement, const N: usize> Narrow<T> for [T; N] {
    type Output = Self;

    fn narrow_mul(&self, other: &T) -> Self {
        std::array::from_fn(|i| self[i].mul(other))
    }
    fn narrow_exp(&self, other: &T::Scalar) -> Self {
        std::array::from_fn(|i| self[i].exp(other))
    }
    fn narrow_equals(&self, other: &T) -> bool {
        for item in self {
            if !item.equals(other) {
                return false;
            }
        }
        true
    }
}

impl<T: GroupElement, const N: usize> Widen<[T; N]> for T {
    type Output = [T; N];

    fn widen_mul(&self, other: &[T; N]) -> Self::Output {
        std::array::from_fn(|i| self.mul(&other[i]))
    }
    fn widen_exp(&self, other: &[T::Scalar; N]) -> Self::Output {
        std::array::from_fn(|i| self.exp(&other[i]))
    }
    fn widen_equals(&self, other: &[T; N]) -> bool {
        for item in other {
            if !item.equals(self) {
                return false;
            }
        }
        true
    }
}
