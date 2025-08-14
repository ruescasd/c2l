use crate::context::Context;
use crate::traits::element::GroupElement;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use crate::utils::serialization::VSerializable;
use vser_derive::VSerializable as VSer;

#[derive(Debug, VSer)]
pub struct CPProof<C: Context> {
    pub c1: C::Element,
    pub c2: C::Element,
    pub response: C::Scalar,
}

impl<C: Context> CPProof<C> {
    pub fn new(c1: C::Element, c2: C::Element, response: C::Scalar) -> Self {
        CPProof { c1, c2, response }
    }
}

pub fn prove<C: Context>(
    secret_x: &C::Scalar,
    g1: &C::Element,
    g2: &C::Element,
    public_y1: &C::Element,
    public_y2: &C::Element,
) -> CPProof<C>
where
{
    let v_scalar = C::random_scalar();
    let t1_element = g1.exp(&v_scalar);
    let t2_element = g2.exp(&v_scalar);
    let g1_bytes = g1.ser();
    let g2_bytes = g2.ser();
    let y1_bytes = public_y1.ser();
    let y2_bytes = public_y2.ser();
    let t1_bytes = t1_element.ser();
    let t2_bytes = t2_element.ser();
    let c_scalar = C::G::hash_to_scalar(
        &[
            g1_bytes.as_ref(),
            g2_bytes.as_ref(),
            y1_bytes.as_ref(),
            y2_bytes.as_ref(),
            t1_bytes.as_ref(),
            t2_bytes.as_ref(),
        ],
        &[b"g1", b"g2", b"public_y1", b"public_y2", b"t1", b"t2"],
    );
    let cx_scalar = c_scalar.mul(secret_x);
    let s_scalar = v_scalar.add(&cx_scalar);
    CPProof::<C>::new(t1_element, t2_element, s_scalar)
}

pub fn verify<C: Context>(
    g1: &C::Element,
    g2: &C::Element,
    public_y1: &C::Element,
    public_y2: &C::Element,
    proof: &CPProof<C>,
) -> bool {
    let s_scalar = &proof.response;
    let g1_bytes = g1.ser();
    let g2_bytes = g2.ser();
    let y1_bytes = public_y1.ser();
    let y2_bytes = public_y2.ser();
    let t1_bytes = proof.c1.ser();
    let t2_bytes = proof.c2.ser();
    let c_scalar = C::G::hash_to_scalar(
        &[
            g1_bytes.as_ref(),
            g2_bytes.as_ref(),
            y1_bytes.as_ref(),
            y2_bytes.as_ref(),
            t1_bytes.as_ref(),
            t2_bytes.as_ref(),
        ],
        &[b"g1", b"g2", b"public_y1", b"public_y2", b"t1", b"t2"],
    );
    let g1_s = g1.exp(s_scalar);
    let y1_c = public_y1.exp(&c_scalar);
    let t1_y1_c = proof.c1.mul(&y1_c);
    let check1 = g1_s == t1_y1_c;
    let g2_s = g2.exp(s_scalar);
    let y2_c = public_y2.exp(&c_scalar);
    let t2_y2_c = proof.c2.mul(&y2_c);
    let check2 = g2_s == t2_y2_c;
    check1 && check2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Context;
    use crate::context::P256Ctx as PCtx;
    use crate::context::RistrettoCtx as RCtx;
    use crate::utils::serialization::{FDeserializable, FSerializable};

    #[test]
    fn test_chaum_pedersen_proof_valid_ristretto() {
        test_chaum_pedersen_proof_valid::<RCtx>();
    }

    #[test]
    fn test_chaum_pedersen_proof_serialization_ristretto() {
        test_chaum_pedersen_proof_serialization::<RCtx>();
    }

    #[test]
    fn test_chaum_pedersen_proof_invalid_ristretto() {
        test_chaum_pedersen_proof_invalid::<RCtx>();
    }

    #[test]
    fn test_chaum_pedersen_proof_valid_p256() {
        test_chaum_pedersen_proof_valid::<PCtx>();
    }

    #[test]
    fn test_chaum_pedersen_proof_serialization_p256() {
        test_chaum_pedersen_proof_serialization::<PCtx>();
    }

    #[test]
    fn test_chaum_pedersen_proof_invalid_p256() {
        test_chaum_pedersen_proof_invalid::<PCtx>();
    }

    fn test_chaum_pedersen_proof_valid<Ctx: Context>() {
        let secret_x = Ctx::random_scalar();
        let g1 = Ctx::random_element();
        let g2 = Ctx::random_element();
        let public_y1 = g1.exp(&secret_x);
        let public_y2 = g2.exp(&secret_x);
        let proof: CPProof<Ctx> = prove(&secret_x, &g1, &g2, &public_y1, &public_y2);
        assert!(
            verify(&g1, &g2, &public_y1, &public_y2, &proof),
            "Verification of a valid Chaum-Pedersen proof should succeed"
        );
    }

    fn test_chaum_pedersen_proof_serialization<Ctx: Context>() {
        let secret_x = Ctx::random_scalar();
        let g1 = Ctx::random_element();
        let g2 = Ctx::random_element();
        let public_y1 = g1.exp(&secret_x);
        let public_y2 = g2.exp(&secret_x);
        let proof: CPProof<Ctx> = prove(&secret_x, &g1, &g2, &public_y1, &public_y2);
        let proof_bytes = proof.ser_f();
        assert_eq!(proof_bytes.len(), CPProof::<Ctx>::size_bytes());

        let parsed_proof = CPProof::<Ctx>::deser_f(&proof_bytes).unwrap();
        assert!(
            verify(&g1, &g2, &public_y1, &public_y2, &parsed_proof),
            "Verification of a parsed valid Chaum-Pedersen proof should succeed"
        );

        assert_eq!(proof.c1, parsed_proof.c1, "c1 should match");
        assert_eq!(proof.c2, parsed_proof.c2, "c1 should match");
        assert_eq!(proof.response, parsed_proof.response, "s should match");
    }

    fn test_chaum_pedersen_proof_invalid<Ctx: Context>() {
        let secret_x = Ctx::random_scalar();
        let g1 = Ctx::random_element();
        let g2 = Ctx::random_element();
        let public_y1 = g1.exp(&secret_x);
        let public_y2 = g2.exp(&secret_x);
        let proof: CPProof<Ctx> = prove(&secret_x, &g1, &g2, &public_y1, &public_y2);
        let original_s = proof.response;
        let tampered_s = original_s.add(&Ctx::Scalar::one());
        let tampered_proof = CPProof::<Ctx>::new(proof.c1, proof.c2, tampered_s);
        assert!(
            !verify::<Ctx>(&g1, &g2, &public_y1, &public_y2, &tampered_proof),
            "Verification of a Chaum-Pedersen proof with a tampered response 's' should fail"
        );
    }
}
