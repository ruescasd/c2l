use crate::context::Context;
use crate::traits::element::GroupElement;
use crate::traits::element::Narrow;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use crate::utils::serialization::VSerializable;
use vser_derive::VSerializable as VSer;

#[derive(Debug, VSer)]
pub struct DlogEqProof<C: Context, const N: usize> {
    pub big_a_0: C::Element,
    pub big_a_1: [C::Element; N],
    pub k: C::Scalar,
}

impl<C: Context, const N: usize> DlogEqProof<C, N> {
    pub fn new(big_a_0: C::Element, big_a_1: [C::Element; N], k: C::Scalar) -> Self {
        DlogEqProof {
            big_a_0,
            big_a_1,
            k,
        }
    }

    pub fn prove(
        secret_x: &C::Scalar,
        g0: &C::Element,
        y0: &C::Element,
        g1: &[C::Element; N],
        y1: &[C::Element; N],
        context: &[u8],
    ) -> DlogEqProof<C, N> {
        let a = C::random_scalar();
        let big_a_0 = g0.exp(&a);
        let big_a_1 = g1.narrow_exp(&a);

        let (input, dsts) = Self::challenge_input(context, g0, g1, y0, y1, &big_a_0, &big_a_1);
        let input: Vec<&[u8]> = input.iter().map(|v| v.as_slice()).collect();
        let v = C::G::hash_to_scalar(&input, &dsts);

        let vx = v.mul(secret_x);
        let k = a.add(&vx);
        Self::new(big_a_0, big_a_1, k)
    }

    pub fn verify(
        &self,
        g0: &C::Element,
        y0: &C::Element,
        g1: &[C::Element; N],
        y1: &[C::Element; N],
        context: &[u8],
    ) -> bool {
        let k = &self.k;

        let (input, dsts) =
            Self::challenge_input(context, g0, g1, y0, y1, &self.big_a_0, &self.big_a_1);
        let input: Vec<&[u8]> = input.iter().map(|v| v.as_slice()).collect();
        let v = C::G::hash_to_scalar(&input, &dsts);

        let y0_v = y0.exp(&v);
        let y0_v_big_a_0 = y0_v.mul(&self.big_a_0);
        let g0_k = g0.exp(k);
        let check1 = y0_v_big_a_0.equals(&g0_k);

        let y1_v = y1.narrow_exp(&v);
        let y1_v_big_a_1 = y1_v.mul(&self.big_a_1);
        let g1_k = g1.narrow_exp(k);
        let check2 = y1_v_big_a_1.equals(&g1_k);
        check1 && check2
    }

    const DS_TAGS: [&[u8]; 7] = [
        b"dlogeq_proof_context",
        b"g0",
        b"g1",
        b"y0",
        b"y1",
        b"big_a_0",
        b"big_a_1",
    ];

    fn challenge_input(
        context: &[u8],
        g0: &C::Element,
        g1: &[C::Element; N],
        y0: &C::Element,
        y1: &[C::Element; N],
        big_a_0: &C::Element,
        big_a_1: &[C::Element; N],
    ) -> ([Vec<u8>; 7], [&'static [u8]; 7]) {
        let a = [
            context.to_vec(),
            g0.ser(),
            g1.ser(),
            y0.ser(),
            y1.ser(),
            big_a_0.ser(),
            big_a_1.ser(),
        ];

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
    fn test_dlogeq_proof_valid_ristretto() {
        test_dlogeq_proof_valid::<RCtx>();
    }

    #[test]
    fn test_dlogeq_proof_serialization_ristretto() {
        test_dlogeq_proof_serialization::<RCtx>();
    }

    #[test]
    fn test_dlogeq_proof_invalid_ristretto() {
        test_dlogeq_proof_invalid::<RCtx>();
    }

    #[test]
    fn test_dlogeq_proof_valid_p256() {
        test_dlogeq_proof_valid::<PCtx>();
    }

    #[test]
    fn dlogeq_proof_serialization_p256() {
        test_dlogeq_proof_serialization::<PCtx>();
    }

    #[test]
    fn test_dlogeq_proof_invalid_p256() {
        test_dlogeq_proof_invalid::<PCtx>();
    }

    fn test_dlogeq_proof_valid<Ctx: Context>() {
        let secret_x = Ctx::random_scalar();
        let g1 = Ctx::random_element();
        let g2 = Ctx::random_element();
        let g3 = Ctx::random_element();

        let public_y1 = g1.exp(&secret_x);
        let public_y2 = g2.exp(&secret_x);
        let public_y3 = g3.exp(&secret_x);

        let gn = [g2, g3];
        let public_yn = [public_y2, public_y3];

        let proof: DlogEqProof<Ctx, 2> =
            DlogEqProof::<Ctx, 2>::prove(&secret_x, &g1, &public_y1, &gn, &public_yn, &vec![]);
        assert!(
            proof.verify(&g1, &public_y1, &gn, &public_yn, &vec![]),
            "Verification of a valid DlogEqProof proof should succeed"
        );
    }

    fn test_dlogeq_proof_serialization<Ctx: Context>() {
        let secret_x = Ctx::random_scalar();
        let g1 = Ctx::random_element();
        let gn = [Ctx::random_element(), Ctx::random_element()];

        let public_y1 = g1.exp(&secret_x);
        let public_yn = gn.narrow_exp(&secret_x);

        let proof: DlogEqProof<Ctx, 2> =
            DlogEqProof::prove(&secret_x, &g1, &public_y1, &gn, &public_yn, &vec![]);
        let proof_bytes = proof.ser_f();
        assert_eq!(proof_bytes.len(), DlogEqProof::<Ctx, 2>::size_bytes());

        let parsed_proof = DlogEqProof::<Ctx, 2>::deser_f(&proof_bytes).unwrap();
        assert!(
            parsed_proof.verify(&g1, &public_y1, &gn, &public_yn, &vec![]),
            "Verification of a parsed valid Chaum-Pedersen proof should succeed"
        );

        assert_eq!(proof.big_a_0, parsed_proof.big_a_0, "c1 should match");
        assert_eq!(proof.big_a_1, parsed_proof.big_a_1, "c1 should match");
        assert_eq!(proof.k, parsed_proof.k, "s should match");
    }

    fn test_dlogeq_proof_invalid<Ctx: Context>() {
        let secret_x = Ctx::random_scalar();
        let g1 = Ctx::random_element();
        let gn = [Ctx::random_element(), Ctx::random_element()];

        let public_y1 = g1.exp(&secret_x);
        let public_yn = gn.narrow_exp(&secret_x);

        let proof: DlogEqProof<Ctx, 2> =
            DlogEqProof::prove(&secret_x, &g1, &public_y1, &gn, &public_yn, &vec![]);

        let original_s = proof.k;
        let tampered_k = original_s.add(&Ctx::Scalar::one());
        let tampered_proof = DlogEqProof::<Ctx, 2>::new(proof.big_a_0, proof.big_a_1, tampered_k);
        assert!(
            !tampered_proof.verify(&g1, &public_y1, &gn, &public_yn, &vec![]),
            "Verification of a DlogEq proof with a tampered response 's' should fail"
        );
    }
}
