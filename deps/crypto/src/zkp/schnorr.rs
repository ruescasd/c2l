use crate::context::Context;
use crate::traits::element::GroupElement;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use crate::utils::serialization::VSerializable;
use vser_derive::VSerializable;

#[derive(Debug, VSerializable, PartialEq)]
pub struct SchnorrProof<C: Context> {
    pub big_a: C::Element,
    pub k: C::Scalar,
}

impl<C: Context> SchnorrProof<C> {
    pub fn new(big_a: C::Element, k: C::Scalar) -> Self {
        Self { big_a, k }
    }

    pub fn prove(g: &C::Element, y: &C::Element, secret_x: &C::Scalar) -> SchnorrProof<C> {
        let a = C::random_scalar();
        let big_a = g.exp(&a);

        let (input, dsts) = Self::challenge_input(g, y, &big_a);
        let input: Vec<&[u8]> = input.iter().map(|v| v.as_slice()).collect();
        let v = C::G::hash_to_scalar(&input, &dsts);

        let k = a.add(&v.mul(secret_x));

        Self::new(big_a, k)
    }

    pub fn verify(&self, g: &C::Element, y: &C::Element) -> bool {
        let big_a = &self.big_a;
        let k = &self.k;

        let (input, dsts) = Self::challenge_input(g, y, big_a);
        let input: Vec<&[u8]> = input.iter().map(|v| v.as_slice()).collect();
        let v = C::G::hash_to_scalar(&input, &dsts);

        let g_k = C::G::generator().exp(k);
        let y_v = y.exp(&v);
        let y_v_big_a = y_v.mul(big_a);

        y_v_big_a.equals(&g_k)
    }

    #[crate::warning("Challenge inputs are incomplete.")]
    const DS_TAGS: [&[u8]; 3] = [b"g", b"public_y", b"big_a"];
    fn challenge_input(
        g: &C::Element,
        y: &C::Element,
        big_a: &C::Element,
    ) -> ([Vec<u8>; 3], [&'static [u8]; 3]) {
        let a = [g.ser(), y.ser(), big_a.ser()];

        (a, Self::DS_TAGS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Context;
    use crate::context::P256Ctx as PCtx;
    use crate::context::RistrettoCtx as RCtx;
    use crate::utils::serialization::{FDeserializable, FSerializable};

    #[test]
    fn test_schnorr_proof_valid_ristretto() {
        test_schnorr_proof_valid::<RCtx>();
    }

    #[test]
    fn test_schnorr_proof_invalid_ristretto() {
        test_schnorr_proof_invalid::<RCtx>();
    }

    #[test]
    fn test_schnorr_proof_serialization_ristretto() {
        test_schnorr_proof_serialization::<RCtx>();
    }

    #[test]
    fn test_schnorr_proof_valid_p256() {
        test_schnorr_proof_valid::<PCtx>();
    }

    #[test]
    fn test_schnorr_proof_serialization_p256() {
        test_schnorr_proof_serialization::<PCtx>();
    }

    #[test]
    fn test_schnorr_proof_invalid_p256() {
        test_schnorr_proof_invalid::<PCtx>();
    }

    fn test_schnorr_proof_valid<Ctx: Context>() {
        let g = Ctx::generator();
        let secret_x = Ctx::random_scalar();
        let public_y = g.exp(&secret_x);

        let proof = SchnorrProof::<Ctx>::prove(&g, &public_y, &secret_x);
        assert!(
            proof.verify(&g, &public_y),
            "Verification of a valid proof should succeed"
        );
    }

    fn test_schnorr_proof_serialization<Ctx: Context>() {
        let g = Ctx::generator();
        let secret_x = Ctx::random_scalar();
        let public_y = g.exp(&secret_x);

        let proof = SchnorrProof::<Ctx>::prove(&g, &public_y, &secret_x);

        let proof_bytes = proof.ser_f();
        assert_eq!(proof_bytes.len(), SchnorrProof::<Ctx>::size_bytes());

        let parsed_proof_result = SchnorrProof::<Ctx>::deser_f(&proof_bytes);
        assert!(parsed_proof_result.is_ok());
        let parsed_proof = parsed_proof_result.unwrap();

        assert!(
            parsed_proof.verify(&g, &public_y),
            "Verification of a parsed valid proof should succeed"
        );

        assert_eq!(proof.big_a, parsed_proof.big_a);
        assert_eq!(proof.k, parsed_proof.k);
    }

    fn test_schnorr_proof_invalid<Ctx: Context>() {
        let g = Ctx::generator();
        let secret_x = Ctx::random_scalar();
        let public_y = g.exp(&secret_x);

        let proof = SchnorrProof::<Ctx>::prove(&g, &public_y, &secret_x);

        let original_k = proof.k;
        let one = <Ctx as Context>::Scalar::one();
        let tampered_k = original_k.add(&one);

        let tampered_proof = SchnorrProof::<Ctx>::new(proof.big_a, tampered_k);

        assert!(
            !tampered_proof.verify(&g, &public_y),
            "Verification of a proof with tampered 's' should fail"
        );
    }
}
