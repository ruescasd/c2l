use crate::context::Context;
use crate::traits::element::GroupElement;
use crate::traits::element::Narrow;
use crate::traits::element::Widen as WidenE;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use crate::traits::scalar::Widen as WidenS;
use crate::utils::serialization::VSerializable;
use vser_derive::VSerializable as VSer;

#[derive(Debug, PartialEq, VSer)]
pub struct PlEqProof<C: Context, const N: usize> {
    pub big_a: [[C::Element; N]; 2],
    pub k: [C::Scalar; N],
}

impl<C: Context, const N: usize> PlEqProof<C, N> {
    pub fn new(big_a: [[C::Element; N]; 2], k: [C::Scalar; N]) -> Self {
        PlEqProof { big_a, k }
    }

    pub fn prove(
        y: &C::Element,
        z: &C::Element,
        u_b: &[C::Element; N],
        v_b: &[C::Element; N],
        u_a: &[C::Element; N],
        r: &[C::Scalar; N],
    ) -> PlEqProof<C, N> {
        let g = C::generator();
        let mut rng = C::get_rng();
        let a_prime = <[C::Scalar; N]>::random(&mut rng);
        let a = a_prime.mul(r);
        let big_a_g = g.widen_exp(&a);
        let big_a_z = z.widen_exp(&a);

        let big_a = [big_a_g, big_a_z];

        let (input, dsts) = Self::challenge_input(&g, y, z, u_b, v_b, u_a, &big_a);
        let input: Vec<&[u8]> = input.iter().map(|v| v.as_slice()).collect();
        let v = C::G::hash_to_scalar(&input, &dsts);

        let vr = v.widen_mul(r);
        let k = vr.add(&a);

        PlEqProof::new(big_a, k)
    }

    pub fn verify(
        &self,
        y: &C::Element,
        z: &C::Element,
        u_b: &[C::Element; N],
        v_b: &[C::Element; N],
        u_a: &[C::Element; N],
    ) -> bool {
        let g = C::generator();
        let (input, dsts) = Self::challenge_input(&g, y, z, u_b, v_b, u_a, &self.big_a);
        let input: Vec<&[u8]> = input.iter().map(|v| v.as_slice()).collect();
        let v = C::G::hash_to_scalar(&input, &dsts);

        let f_k = [g, z.clone()].map(|e| e.widen_exp(&self.k));

        let u_v = [u_b, u_a].map(|e| e.narrow_exp(&v));

        let u_v_big_a = u_v.mul(&self.big_a);

        u_v_big_a.equals(&f_k)
    }

    #[crate::warning("Challenge inputs are incomplete.")]
    const DS_TAGS: [&[u8]; 7] = [b"g", b"y", b"z", b"u_b", b"v_b", b"u_a", b"big_a"];

    fn challenge_input(
        g: &C::Element,
        y: &C::Element,
        z: &C::Element,
        u_b: &[C::Element; N],
        v_b: &[C::Element; N],
        u_a: &[C::Element; N],
        big_a: &[[C::Element; N]; 2],
    ) -> ([Vec<u8>; 7], [&'static [u8]; 7]) {
        let a = [
            g.ser(),
            y.ser(),
            z.ser(),
            u_b.ser(),
            v_b.ser(),
            u_a.ser(),
            big_a.ser(),
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
    use crate::cryptosystem::elgamal::KeyPair as EGKeyPair;
    use crate::cryptosystem::naoryung::KeyPair;
    use crate::traits::scalar::Narrow;
    use crate::utils::serialization::{FDeserializable, FSerializable};

    #[test]
    fn test_pleq_proof_valid_ristretto() {
        test_pleq_proof_valid::<RCtx>();
    }

    #[test]
    fn test_pleq_proof_valid_p256() {
        test_pleq_proof_valid::<PCtx>();
    }

    #[test]
    fn test_pleq_proof_serialization_ristretto() {
        test_pleq_proof_serialization::<RCtx>();
    }

    #[test]
    fn test_pleq_proof_serialization_p256() {
        test_pleq_proof_serialization::<PCtx>();
    }

    fn test_pleq_proof_valid<Ctx: Context>() {
        let eg = EGKeyPair::<Ctx>::generate();
        let ny = KeyPair::generate(&eg);

        let msg = [Ctx::random_element(), Ctx::random_element()];
        let mut rng = Ctx::get_rng();
        let r = <[Ctx::Scalar; 2]>::random(&mut rng);
        let ciphertext = ny.encrypt_with_r(&msg, &r);

        let proof = PlEqProof::<Ctx, 2>::prove(
            &ny.pk_b,
            &ny.pk_a,
            &ciphertext.u_b,
            &ciphertext.v_b,
            &ciphertext.u_a,
            &r,
        );

        let ok = proof.verify(
            &ny.pk_b,
            &ny.pk_a,
            &ciphertext.u_b,
            &ciphertext.v_b,
            &ciphertext.u_a,
        );

        assert!(ok);

        let original_k = proof.k;
        let tampered_k = original_k.narrow_add(&Ctx::Scalar::one());

        let tampered_proof = PlEqProof::<Ctx, 2>::new(proof.big_a, tampered_k);

        let not_ok = tampered_proof.verify(
            &ny.pk_b,
            &ny.pk_a,
            &ciphertext.u_b,
            &ciphertext.v_b,
            &ciphertext.u_a,
        );

        assert!(!not_ok);
    }

    fn test_pleq_proof_serialization<Ctx: Context>() {
        let eg = EGKeyPair::<Ctx>::generate();
        let ny = KeyPair::generate(&eg);

        let msg = [Ctx::random_element(), Ctx::random_element()];
        let mut rng = Ctx::get_rng();
        let r = <[Ctx::Scalar; 2]>::random(&mut rng);
        let ciphertext = ny.encrypt_with_r(&msg, &r);

        let proof = PlEqProof::<Ctx, 2>::prove(
            &ny.pk_b,
            &ny.pk_a,
            &ciphertext.u_b,
            &ciphertext.v_b,
            &ciphertext.u_a,
            &r,
        );
        let bytes = proof.ser_f();
        let proof_d = PlEqProof::<Ctx, 2>::deser_f(&bytes).unwrap();

        let ok = proof_d.verify(
            &ny.pk_b,
            &ny.pk_a,
            &ciphertext.u_b,
            &ciphertext.v_b,
            &ciphertext.u_a,
        );

        assert!(ok);
    }
}
