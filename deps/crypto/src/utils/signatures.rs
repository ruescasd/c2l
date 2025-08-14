use std::marker::PhantomData;

use ed25519::signature::{Signer, Verifier};
use ed25519_dalek::ed25519;

use crate::utils::{rng::CRng, Error};

pub trait Signatures<R: CRng> {
    type Signer;
    type Verifier;
    type Signature;

    fn generate(rng: &mut R) -> Self::Signer;
    fn sign(msg: &[u8], sk: &Self::Signer) -> Self::Signature;
    fn verify(msg: &[u8], signature: &Self::Signature, vk: &Self::Verifier) -> Result<(), Error>;
}
pub struct Ed25519<R: CRng>(PhantomData<R>);
impl<R: CRng> Signatures<R> for Ed25519<R> {
    type Signer = ed25519_dalek::SigningKey;
    type Verifier = ed25519_dalek::VerifyingKey;
    type Signature = ed25519_dalek::Signature;

    fn generate(rng: &mut R) -> ed25519_dalek::SigningKey {
        Self::Signer::generate(rng)
    }
    fn sign(msg: &[u8], sk: &ed25519_dalek::SigningKey) -> ed25519_dalek::Signature {
        sk.sign(msg)
    }
    fn verify(
        msg: &[u8],
        signature: &ed25519_dalek::Signature,
        vk: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), Error> {
        vk.verify(msg, signature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_signatures_dalek() {
        type Sig = Ed25519<OsRng>;

        let mut csprng = OsRng;
        let sk = Sig::generate(&mut csprng);

        let message: &[u8] = b"message";
        let signature = <Sig as Signatures<OsRng>>::sign(message, &sk);

        let vk = sk.verifying_key();
        let ok = <Sig as Signatures<OsRng>>::verify(message, &signature, &vk);

        assert!(ok.is_ok());
    }

    #[test]
    fn test_signatures_context() {
        use crate::context::Context;

        let mut csprng = OsRng;
        type Sig = <crate::context::RistrettoCtx as Context>::Signatures;
        let sk = Sig::generate(&mut csprng);

        let message: &[u8] = b"message";
        let signature = Sig::sign(message, &sk);

        let vk = sk.verifying_key();
        let ok = Sig::verify(message, &signature, &vk);

        assert!(ok.is_ok());
    }
}
