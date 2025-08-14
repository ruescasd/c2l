use crate::context::Context;
use crate::traits::element::GroupElement;
use crate::traits::element::{Narrow, Widen};
use crate::traits::scalar::GroupScalar;
use vser_derive::VSerializable;

#[derive(Debug, PartialEq, VSerializable)]
pub struct KeyPair<C: Context> {
    pub skey: C::Scalar,
    pub pkey: C::Element,
}
impl<C: Context> KeyPair<C> {
    pub fn new(skey: <C as Context>::Scalar, pkey: <C as Context>::Element) -> KeyPair<C> {
        KeyPair { skey, pkey }
    }
}

impl<C: Context> KeyPair<C> {
    pub fn generate() -> Self {
        let skey = C::random_scalar();
        let pkey = C::generator().exp(&skey);
        KeyPair { skey, pkey }
    }

    #[crate::warning("Duplicated in PublicKey impl")]
    pub fn encrypt_with_r<const W: usize>(
        &self,
        msg: &[C::Element; W],
        r: &[C::Scalar; W],
    ) -> Ciphertext<C, W> {
        let g = C::generator();

        let u = g.widen_exp(r);
        let v = self.pkey.widen_exp(r);
        let v = msg.mul(&v);

        Ciphertext([u, v])
    }

    #[crate::warning("Duplicated in PublicKey impl")]
    pub fn encrypt<const W: usize>(&self, msg: &[C::Element; W]) -> Ciphertext<C, W> {
        let mut rng = C::get_rng();
        let r = <[C::Scalar; W]>::random(&mut rng);

        self.encrypt_with_r(msg, &r)
    }

    pub fn decrypt<const W: usize>(&self, message: &Ciphertext<C, W>) -> [C::Element; W] {
        decrypt::<C, W>(message.u(), message.v(), &self.skey)
    }
}

// This function is used to decrypt messages without
// having to allocate a KeyPair or a Ciphertext.
#[inline(always)]
pub fn decrypt<C: Context, const W: usize>(
    u: &[C::Element; W],
    v: &[C::Element; W],
    sk: &C::Scalar,
) -> [C::Element; W] {
    let u_pow_neg_x = u.narrow_exp(&sk.neg());

    v.mul(&u_pow_neg_x)
}

#[derive(Debug, PartialEq, Clone, VSerializable)]
pub struct Ciphertext<C: Context, const W: usize>(pub [[C::Element; W]; 2]);
impl<C: Context, const W: usize> Ciphertext<C, W> {
    pub fn new(u: [C::Element; W], v: [C::Element; W]) -> Self {
        Ciphertext([u, v])
    }
    pub fn re_encrypt(&self, r_n: &[C::Scalar; W], pk: &C::Element) -> Self {
        let g = C::generator();
        // (g, y)^r
        let one = [g, pk.clone()].map(|v| v.widen_exp(r_n));
        let re_encrypted = self.0.mul(&one);

        Self(re_encrypted)
    }
    pub fn u(&self) -> &[C::Element; W] {
        &self.0[0]
    }
    pub fn v(&self) -> &[C::Element; W] {
        &self.0[1]
    }
    pub fn map<F, U>(self, f: F) -> [U; 2]
    where
        F: FnMut([C::Element; W]) -> U,
    {
        self.0.map(f)
    }
    pub fn map_ref<F, U>(&self, mut f: F) -> [U; 2]
    where
        F: FnMut(&[C::Element; W]) -> U,
    {
        std::array::from_fn(|i| {
            let uv = &self.0[i];
            f(uv)
        })
    }
}

#[derive(Debug, PartialEq, VSerializable)]
pub struct PublicKey<C: Context> {
    pub y: C::Element,
}
impl<C: Context> PublicKey<C> {
    pub fn new(y: C::Element) -> Self {
        Self { y }
    }
    pub fn from_keypair(keypair: &KeyPair<C>) -> Self {
        Self {
            y: keypair.pkey.clone(),
        }
    }
    pub fn encrypt<const W: usize>(&self, message: &[C::Element; W]) -> Ciphertext<C, W> {
        let mut rng = C::get_rng();
        let r = <[C::Scalar; W]>::random(&mut rng);

        self.encrypt_with_r(message, &r)
    }

    pub fn encrypt_with_r<const W: usize>(
        &self,
        message: &[C::Element; W],
        r: &[C::Scalar; W],
    ) -> Ciphertext<C, W> {
        let g = C::generator();

        let u = g.widen_exp(r);
        let v = self.y.widen_exp(r);
        let v = message.mul(&v);

        Ciphertext([u, v])
    }
}

#[cfg(test)]
mod tests {
    use crate::context::Context;
    use crate::context::P256Ctx as PCtx;
    use crate::context::RistrettoCtx as RCtx;
    use crate::cryptosystem::elgamal::{Ciphertext, KeyPair};
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
    fn test_elgamal_ristretto() {
        test_elgamal::<RCtx>();
    }

    #[test]
    fn test_elgamal_p256() {
        test_elgamal::<PCtx>();
    }

    #[test]
    fn test_elgamal_serialization_and_decryption_ristretto() {
        test_elgamal_serialization_and_decryption::<RCtx>();
    }

    #[test]
    fn test_elgamal_serialization_and_decryption_p256() {
        test_elgamal_serialization_and_decryption::<PCtx>();
    }

    fn test_keypair_serialization<Ctx: Context>() {
        let keypair = KeyPair::<Ctx>::generate();

        let serialized = keypair.ser_f();
        assert_eq!(serialized.len(), KeyPair::<Ctx>::size_bytes());

        let deserialized = KeyPair::<Ctx>::deser_f(&serialized).unwrap();
        assert_eq!(keypair.pkey, deserialized.pkey);
        assert_eq!(keypair.skey, deserialized.skey);
    }

    fn test_elgamal<Ctx: Context>() {
        let keypair = KeyPair::<Ctx>::generate();
        let message = [Ctx::random_element(), Ctx::random_element()];

        let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message);
        let decrypted_message = keypair.decrypt(&ciphertext);
        assert_eq!(message, decrypted_message);
    }

    fn test_elgamal_serialization_and_decryption<Ctx: Context>() {
        let keypair = KeyPair::<Ctx>::generate();
        let message = [Ctx::random_element(), Ctx::random_element()];

        let ciphertext: Ciphertext<Ctx, 2> = keypair.encrypt(&message);

        let serialized_ct = ciphertext.ser_f();
        assert_eq!(serialized_ct.len(), Ciphertext::<Ctx, 2>::size_bytes());

        let deserialized_ct = Ciphertext::<Ctx, 2>::deser_f(&serialized_ct).unwrap();

        assert_eq!(ciphertext, deserialized_ct);

        let decrypted_message = keypair.decrypt(&deserialized_ct);
        assert_eq!(message, decrypted_message);
    }
}
