use crate::context::Context;
use crate::cryptosystem::elgamal;
use crate::cryptosystem::elgamal::KeyPair as EGKeyPair;
use crate::traits::element::GroupElement;
use crate::traits::element::Widen;
use crate::traits::scalar::GroupScalar;
use crate::utils::Error;
use crate::zkp::pleq::PlEqProof;
use vser_derive::VSerializable;

#[derive(Debug, PartialEq, VSerializable)]
pub struct KeyPair<C: Context> {
    // x
    pub sk_b: <C as Context>::Scalar,
    // y = g^x
    pub pk_b: <C as Context>::Element,
    // w
    pub sk_a: <C as Context>::Scalar,
    // z = y^w
    pub pk_a: <C as Context>::Element,
}

impl<C: Context> KeyPair<C> {
    pub fn generate(elgamal_keypair: &EGKeyPair<C>) -> Self {
        let sk_a = C::random_scalar();
        let pk_a = C::generator().exp(&sk_a);
        let sk_b = elgamal_keypair.skey.clone();
        let pk_b = elgamal_keypair.pkey.clone();
        KeyPair {
            sk_a,
            pk_a,
            sk_b,
            pk_b,
        }
    }

    pub fn encrypt_with_r<const N: usize>(
        &self,
        message: &[C::Element; N],
        r: &[C::Scalar; N],
    ) -> Ciphertext<C, N> {
        let g = C::generator();

        let u_b = g.widen_exp(r);
        let v_b = self.pk_b.widen_exp(r);
        let v_b = message.mul(&v_b);
        let u_a = self.pk_a.widen_exp(r);

        let proof = PlEqProof::<C, N>::prove(&self.pk_b, &self.pk_a, &u_b, &v_b, &u_a, r);

        Ciphertext::new(u_b, v_b, u_a, proof)
    }

    pub fn encrypt<const N: usize>(&self, message: &[C::Element; N]) -> Ciphertext<C, N> {
        let mut rng = C::get_rng();
        let r = <[C::Scalar; N]>::random(&mut rng);

        self.encrypt_with_r(message, &r)
    }

    pub fn strip<const N: usize>(
        &self,
        c: Ciphertext<C, N>,
    ) -> Result<elgamal::Ciphertext<C, N>, Error> {
        let proof_ok = c
            .proof
            .verify(&self.pk_b, &self.pk_a, &c.u_b, &c.v_b, &c.u_a);

        if proof_ok {
            Ok(elgamal::Ciphertext::<C, N>::new(c.u_b, c.v_b))
        } else {
            Err(Error::NaorYungStripError(
                "Proof failed to validate for naor yung ciphertext".into(),
            ))
        }
    }

    // includes duplicated stripping code to avoid allocations
    pub fn decrypt<const N: usize>(&self, c: &Ciphertext<C, N>) -> Result<[C::Element; N], Error> {
        let proof_ok = c
            .proof
            .verify(&self.pk_b, &self.pk_a, &c.u_b, &c.v_b, &c.u_a);

        if proof_ok {
            let decrypted_element = elgamal::decrypt::<C, N>(&c.u_b, &c.v_b, &self.sk_b);

            Ok(decrypted_element)
        } else {
            Err(Error::NaorYungStripError(
                "Proof failed to validate for naor yung ciphertext".into(),
            ))
        }
    }
}

#[derive(Debug, PartialEq, VSerializable)]
pub struct Ciphertext<C: Context, const N: usize> {
    // u_b = g^r
    pub u_b: [C::Element; N],
    // v_b = my^r where pk_b = y
    pub v_b: [C::Element; N],
    // u_a = z^r where pk_a = z
    pub u_a: [C::Element; N],
    pub proof: PlEqProof<C, N>,
}

impl<C: Context, const N: usize> Ciphertext<C, N> {
    pub fn new(
        u_b: [C::Element; N],
        v_b: [C::Element; N],
        u_a: [C::Element; N],
        proof: PlEqProof<C, N>,
    ) -> Self {
        Ciphertext {
            u_b,
            v_b,
            u_a,
            proof,
        }
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
    fn test_keypair_serialization_ristretto() {
        test_keypair_serialization::<RCtx>();
    }

    #[test]
    fn test_keypair_serialization_p256() {
        test_keypair_serialization::<PCtx>();
    }

    #[test]
    fn test_encryption_ristretto() {
        test_encryption::<RCtx>();
    }

    #[test]
    fn test_encryption_p256() {
        test_encryption::<PCtx>();
    }

    #[test]
    fn test_serialization_and_decryption_ristretto() {
        test_serialization_and_decryption::<RCtx>();
    }

    #[test]
    fn test_serialization_and_decryption_p256() {
        test_serialization_and_decryption::<PCtx>();
    }

    fn test_keypair_serialization<Ctx: Context>() {
        let eg_keypair = EGKeyPair::<Ctx>::generate();
        let keypair = KeyPair::<Ctx>::generate(&eg_keypair);

        let serialized = keypair.ser_f();
        assert_eq!(serialized.len(), KeyPair::<Ctx>::size_bytes());

        let deserialized = KeyPair::<Ctx>::deser_f(&serialized).unwrap();
        assert_eq!(keypair, deserialized);
    }

    fn test_encryption<Ctx: Context>() {
        let eg_keypair = EGKeyPair::<Ctx>::generate();
        let keypair = KeyPair::<Ctx>::generate(&eg_keypair);
        let message = [Ctx::random_element(), Ctx::random_element()];

        let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message);
        let decrypted_message = keypair.decrypt(&ciphertext).unwrap();
        assert_eq!(message, decrypted_message);
    }

    fn test_serialization_and_decryption<Ctx: Context>() {
        let eg_keypair = EGKeyPair::<Ctx>::generate();
        let keypair = KeyPair::<Ctx>::generate(&eg_keypair);
        let message = [Ctx::random_element(), Ctx::random_element()];

        let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message);
        let serialized_ct = ciphertext.ser_f();
        assert_eq!(serialized_ct.len(), Ciphertext::<Ctx, 2>::size_bytes());

        let deserialized_ct = Ciphertext::<Ctx, 2>::deser_f(&serialized_ct).unwrap();

        assert_eq!(ciphertext, deserialized_ct);

        let decrypted_message = keypair.decrypt(&deserialized_ct).unwrap();
        assert_eq!(message, decrypted_message);
    }
}
