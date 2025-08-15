use std::marker::PhantomData;
use crypto::dkgd::{DecryptionFactor, VerifiableShares};
use ed25519_dalek::PublicKey as SPublicKey;
use serde::{Deserialize, Serialize};

use crypto::cryptosystem::naoryung::{Ciphertext as NYCiphertext};
use crypto::cryptosystem::Plaintext;
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
pub struct Keyshares<A: Application> {
    pub shares: VerifiableShares<A::Context, {A::T}, {A::P}>,
    pub phantom_a: PhantomData<A>,
}

#[derive(Serialize, Deserialize)]
pub struct Ballots<A: Application> {
    pub ciphertexts: Vec<NYCiphertext<A::Context, {A::W}>>,
    pub phantom_a: PhantomData<A>,
}

#[derive(Serialize, Deserialize)]
pub struct Mix<A: Application> {
    pub mixed_ballots: Vec<Ciphertext<A::Context, {A::W}>>,
    pub proof: CShuffleProof<A::Context, {A::W}>,
    pub phantom_a: PhantomData<A>,
}

#[derive(Serialize, Deserialize)]
pub struct PartialDecryption<A: Application> {
    pub pd_ballots: Vec<DecryptionFactor<A::Context, {A::W}>>,
    pub phantom_a: PhantomData<A>,
}

#[derive(Serialize, Deserialize)]
pub struct Plaintexts<A: Application> {
    pub plaintexts: Vec<Plaintext<A::Context, {A::W}>>,
    pub phantom_a: PhantomData<A>,
}