use std::marker::PhantomData;
use crypto::dkgd::{DecryptionFactor, VerifiableShares};
use ed25519_dalek::PublicKey as SPublicKey;
use serde::{Deserialize, Serialize};

use crypto::cryptosystem::naoryung::{Ciphertext as NYCiphertext};
use crypto::zkp::shuffle::ShuffleProof as CShuffleProof;
use crypto::cryptosystem::elgamal::Ciphertext;
use crate::Application;


#[derive(Serialize, Deserialize, Eq, PartialEq, Debug)]
pub struct Config<A: Application> {
    pub id: [u8; 16],
    pub contests: u32, 
    pub ballotbox: SPublicKey, 
    pub trustees: Vec<SPublicKey>,
    pub phantom_a: PhantomData<A>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Keyshares<A: Application> 
where 
 [(); A::T]:,
 [(); A::P]:,
{
    pub shares: VerifiableShares<A::Context, {A::T}, {A::P}>,
}

#[derive(Serialize, Deserialize)]
pub struct Ballots<A: Application> 
 where 
 [(); A::W]:,
{
    pub ciphertexts: Vec<NYCiphertext<A::Context, {A::W}>>,
}

#[derive(Serialize, Deserialize)]
pub struct Mix<A: Application> 
 where 
 [(); A::W]:,
{
    pub mixed_ballots: Vec<Ciphertext<A::Context, {A::W}>>,
    pub proof: CShuffleProof<A::Context, {A::W}>,
}

#[derive(Serialize, Deserialize)]
pub struct PartialDecryption<A: Application> 
 where 
 [(); A::W]:,
{
    pub pd_ballots: Vec<DecryptionFactor<A::Context, {A::W}>>,
}

#[derive(Serialize, Deserialize, PartialEq)]
#[serde(bound = "A: Application")] 
pub struct Plaintexts<A: Application> 
 where 
 [(); A::W]:,
{
    pub plaintexts: Vec<Plaintext<A>>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Plaintext<A: Application>(pub [<A::Context as Context>::Element; A::W]) where [(); A::W]:;

use serde::{self, de::Error, Deserializer, Serializer};
use crypto::utils::serialization::{VDeserializable, VSerializable};
use crypto::context::Context;

// Plaintext
impl<'de, A: Application> serde::Deserialize<'de> for Plaintext<A> 
where [(); A::W]:
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        let p = <[<A::Context as Context>::Element; A::W]>::deser(&bytes).map_err(D::Error::custom)?;

        Ok(Self(p))
    }
}

impl<A: Application> serde::Serialize for Plaintext<A> 
where [(); A::W]:
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0.ser())
    }
}