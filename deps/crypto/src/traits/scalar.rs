use crate::utils::rng;
use std::array;
use std::fmt::Debug;

pub trait GroupScalar: Sized + Debug + PartialEq {
    fn zero() -> Self;
    fn one() -> Self;
    fn add(&self, other: &Self) -> Self;
    fn sub(&self, other: &Self) -> Self;
    fn mul(&self, other: &Self) -> Self;
    fn neg(&self) -> Self;
    fn inv(&self) -> Option<Self>;
    fn equals(&self, other: &Self) -> bool;

    fn random<R: rng::CRng>(rng: &mut R) -> Self;
}

pub trait Widen<Rhs: GroupScalar>: GroupScalar {
    type Output;

    fn widen_add(&self, other: &Rhs) -> Self::Output;
    fn widen_sub(&self, other: &Rhs) -> Self::Output;
    fn widen_mul(&self, other: &Rhs) -> Self::Output;
    fn widen_equals(&self, other: &Rhs) -> bool;
}

pub trait Narrow<Rhs: GroupScalar>: GroupScalar {
    type Output;

    fn narrow_add(&self, other: &Rhs) -> Self::Output;
    fn narrow_sub(&self, other: &Rhs) -> Self::Output;
    fn narrow_mul(&self, other: &Rhs) -> Self::Output;
    fn narrow_equals(&self, other: &Rhs) -> bool;
}

impl<T: GroupScalar, const N: usize> GroupScalar for [T; N] {
    fn zero() -> Self {
        array::from_fn(|_| T::zero())
    }
    fn one() -> Self {
        array::from_fn(|_| T::one())
    }
    fn random<R: rng::CRng>(rng: &mut R) -> Self {
        array::from_fn(|_| T::random(rng))
    }

    fn add(&self, other: &Self) -> Self {
        array::from_fn(|i| self[i].add(&other[i]))
    }
    fn sub(&self, other: &Self) -> Self {
        array::from_fn(|i| self[i].sub(&other[i]))
    }
    fn mul(&self, other: &Self) -> Self {
        array::from_fn(|i| self[i].mul(&other[i]))
    }
    fn neg(&self) -> Self {
        array::from_fn(|i| self[i].neg())
    }
    fn inv(&self) -> Option<Self> {
        let ret: Option<Vec<T>> = self.iter().map(|s| s.inv()).collect();

        ret.map(|v| v.try_into().expect("impossible"))
    }
    fn equals(&self, other: &Self) -> bool {
        for i in 0..self.len() {
            if self[i] != other[i] {
                return false;
            }
        }
        true
    }
}

impl<T: GroupScalar, const N: usize> Narrow<T> for [T; N] {
    type Output = Self;

    fn narrow_add(&self, other: &T) -> Self {
        std::array::from_fn(|i| self[i].add(other))
    }
    fn narrow_sub(&self, other: &T) -> Self {
        std::array::from_fn(|i| self[i].sub(other))
    }
    fn narrow_mul(&self, other: &T) -> Self {
        std::array::from_fn(|i| self[i].mul(other))
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

impl<T: GroupScalar, const N: usize> Widen<[T; N]> for T {
    type Output = [T; N];

    fn widen_add(&self, other: &[T; N]) -> Self::Output {
        std::array::from_fn(|i| self.add(&other[i]))
    }

    fn widen_sub(&self, other: &[T; N]) -> Self::Output {
        std::array::from_fn(|i| self.sub(&other[i]))
    }

    fn widen_mul(&self, other: &[T; N]) -> Self::Output {
        std::array::from_fn(|i| self.mul(&other[i]))
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
