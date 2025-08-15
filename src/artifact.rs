use std::marker::PhantomData;
use crypto::dkgd::{DecryptionFactor, VerifiableShares};
use ed25519_dalek::PublicKey as SPublicKey;
use serde::{Deserialize, Serialize};

use crypto::cryptosystem::naoryung::{Ciphertext as NYCiphertext};
use crypto::zkp::shuffle::ShuffleProof as CShuffleProof;
use crypto::context::Context;
use crypto::cryptosystem::elgamal::Ciphertext;

use serde::{self, de::Error, Deserializer, Serializer};
use crypto::utils::serialization::{VDeserializable, VSerializable};

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct CConfig<C: Context> {
    pub id: [u8; 16],
    pub contests: u32, 
    pub ballotbox: SPublicKey, 
    pub trustees: Vec<SPublicKey>,
    pub phantom_c: PhantomData<C>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CKeyshares<C: Context, const T: usize, const P: usize> {
    pub shares: VerifiableShares<C, T, P>,
}

#[derive(Serialize, Deserialize)]
pub struct CBallots<C: Context, const W: usize> {
    pub ciphertexts: Vec<NYCiphertext<C, W>>
}

#[derive(Serialize, Deserialize)]
pub struct CMix<C: Context, const W: usize, const T: usize> {
    pub mixed_ballots: Vec<Ciphertext<C, W>>,
    pub proof: CShuffleProof<C, W>,
}

#[derive(Serialize, Deserialize)]
pub struct CPartialDecryption<C: Context, const W: usize> {
    pub pd_ballots: Vec<DecryptionFactor<C, W>>,
}

#[derive(Serialize, Deserialize)]
pub struct CPlaintexts<C: Context, const W: usize> {
    pub plaintexts: Vec<Plaintext<C, W>>
}
#[derive(Debug, PartialEq, Eq)]
pub struct Plaintext<C: Context, const W: usize>(pub [C::Element; W]);

impl<'de, C: Context, const W: usize> serde::Deserialize<'de> for Plaintext<C, W> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        let p = <[<C as Context>::Element; W]>::deser(&bytes).map_err(D::Error::custom)?;

        Ok(Self(p))
    }
}

impl<C: Context, const W: usize> serde::Serialize for Plaintext<C, W> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0.ser())
    }
}