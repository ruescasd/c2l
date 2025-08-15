pub mod elgamal;
pub mod naoryung;

#[derive(Debug, vser_derive::VSerializable, PartialEq, Eq, Hash)]
pub struct Plaintext<C: crate::context::Context, const W: usize>(pub [C::Element; W]);