use std::marker::PhantomData;
use crypto::dkgd::{DecryptionFactor, VerifiableShares};
use ed25519_dalek::PublicKey as SPublicKey;
use serde::{Deserialize, Serialize};

// use crypto::cryptosystem::elgamal::{Ciphertext as CCiphertext, KeyPair as CKeyPair, PublicKey as CPublicKey};
use crypto::cryptosystem::naoryung::{Ciphertext as NYCiphertext};
use crypto::cryptosystem::Plaintext;
use crypto::zkp::shuffle::ShuffleProof as CShuffleProof;
use crypto::context::Context;
use crypto::cryptosystem::elgamal::Ciphertext;


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