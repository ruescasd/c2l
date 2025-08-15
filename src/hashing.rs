use std::marker::{Send, Sync};

use crypto::dkgd::DecryptionFactor;
use crypto::dkgd::DkgCiphertext;
use crypto::cryptosystem::naoryung::{Ciphertext as NYCiphertext, PublicKey};
use crypto::cryptosystem::elgamal::{Ciphertext as EGCiphertext};
use sha2::{Sha512, Sha256, Digest};


pub type Hash = [u8; 64];

trait ConcatWithLength  {
    fn extendl(&mut self, add: &Vec<u8>);
}

impl ConcatWithLength for Vec<u8> {
    fn extendl(&mut self, add: &Vec<u8>) {
        let length = add.len() as u64;
        self.extend(&length.to_le_bytes());
        self.extend(add);
    }
}

pub trait HashBytes {
    fn get_bytes(&self) -> Vec<u8>;
}

pub trait HashTo<T>: Send + Sync {
    fn hash_to(&self, bytes: &[u8]) -> T;
}

/*pub struct RistrettoHasher;

impl HashTo<Scalar> for RistrettoHasher {
    fn hash_to(&self, bytes: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        Scalar::from_hash(hasher)
    }
}

impl HashTo<RistrettoPoint> for RistrettoHasher {
    fn hash_to(&self, bytes: &[u8]) -> RistrettoPoint {
        let mut hasher = Sha512::new();
        hasher.update(bytes);

        RistrettoPoint::from_hash(hasher)
    }
}*/


fn first_bytes<T: HashBytes>(input: T) -> Vec<u8> {
    let mut bytes = input.get_bytes();
    let length = bytes.len() as u64;
    let mut first = length.to_le_bytes().to_vec();
    first.append(&mut bytes);

    first
}

// https://stackoverflow.com/questions/39675949/is-there-a-trait-supplying-iter
fn concat_bytes_iter<'a, H: 'a + HashBytes, I: IntoIterator<Item = &'a H>>(cs: I) -> Vec<u8> {
    cs.into_iter()
    .map(|x| x.get_bytes())
    .fold(vec![], |mut a, b| {
        let length = b.len() as u64;
        a.extend(&length.to_le_bytes());
        a.extend(b);
        a
    })
}

fn concat_bytes<T: HashBytes>(cs: &Vec<T>) -> Vec<u8> {
    concat_bytes_iter(cs)
}

use crate::util;

pub fn hash<T: HashBytes>(data: &T) -> [u8; 64] {
    let bytes = data.get_bytes();
    hash_bytes(bytes)
    /* let mut hasher = Sha512::new();
    hasher.update(bytes);
    util::to_u8_64(&hasher.finalize().to_vec())*/
}

pub fn hash_bytes(bytes: Vec<u8>) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(bytes);
    util::to_u8_64(&hasher.finalize().to_vec())
}

pub fn hash_bytes_256(bytes: Vec<u8>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    util::to_u8_32(&hasher.finalize().to_vec())
}
/* 
impl HashBytes for RistrettoPoint {
    fn get_bytes(&self) -> Vec<u8> {
        self.compress().as_bytes().to_vec()
    }
}

impl HashBytes for Scalar {
    fn get_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}*/

/* 
use crate::ristretto_b::RistrettoGroup;

impl HashBytes for RistrettoGroup {
    fn get_bytes(&self) -> Vec<u8> {
        vec![]
    }
}*/


use ed25519_dalek::PublicKey as SPublicKey;

impl HashBytes for SPublicKey {
    fn get_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

use ed25519_dalek::Signature;

impl HashBytes for Signature {
    fn get_bytes(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}

use crate::statement::Statement;

impl HashBytes for Statement {
    fn get_bytes(&self) -> Vec<u8> {
        let discriminant = self.stype as u8;
        let mut bytes: Vec<u8> = vec![discriminant];
        bytes.extend(&self.contest.to_le_bytes());
        
        for b in self.hashes.iter() {
            bytes.extend(b);
        }

        bytes
    }
}

use crate::statement::SignedStatement;

impl HashBytes for SignedStatement {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = self.statement.get_bytes();
        bytes.extendl(&self.signature.get_bytes());
        
        bytes
    }
}

use crate::artifact::CConfig;
use crypto::context::Context;


impl<C: Context> HashBytes for CConfig<C> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = self.id.to_vec();
        bytes.extend(&self.contests.to_le_bytes());
        bytes.extend(self.ballotbox.get_bytes());
        bytes.extend(concat_bytes(&self.trustees));

        bytes
    }
}

use crate::artifact::CKeyshares;

impl<C: Context, const T: usize, const P: usize> HashBytes for CKeyshares<C, T, P> {
    fn get_bytes(&self) -> Vec<u8> {
        let bytes = bincode::serialize(&self.shares).unwrap();

        bytes
    }
}

use crate::artifact::CBallots;

impl<C: Context, const W: usize, const T: usize> HashBytes for DkgCiphertext<C, W, T> {
    fn get_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl<C: Context, const W: usize> HashBytes for NYCiphertext<C, W> {
    fn get_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl<C: Context, const W: usize> HashBytes for EGCiphertext<C, W> {
    fn get_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl<C: Context, const W: usize> HashBytes for DecryptionFactor<C, W> {
    fn get_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl<C: Context> HashBytes for PublicKey<C> {
    fn get_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

use crypto::cryptosystem::Plaintext;

impl<C: Context, const W: usize> HashBytes for Plaintext<C, W> {
    fn get_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl<C: Context, const W: usize> HashBytes for CBallots<C, W> {
    fn get_bytes(&self) -> Vec<u8> {
        concat_bytes(&self.ciphertexts)
    }
}

use crate::artifact::CMix;

impl<C: Context, const W: usize, const T: usize> HashBytes for CMix<C, W, T> {
    fn get_bytes(&self) -> Vec<u8> {
        let mut bytes = concat_bytes(&self.mixed_ballots);
        bytes.extend(bincode::serialize(&self.proof).unwrap());

        bytes
    }
}

use crate::artifact::CPartialDecryption;

impl<C: Context, const W: usize>  HashBytes for CPartialDecryption<C, W> {
    fn get_bytes(&self) -> Vec<u8> {
        let bytes = concat_bytes(&self.pd_ballots);

        bytes
    }
}

use crate::artifact::CPlaintexts;

impl<C: Context, const W: usize> HashBytes for CPlaintexts<C, W> {
    fn get_bytes(&self) -> Vec<u8> {
        concat_bytes(&self.plaintexts)
    }
}

use crate::action::Act;

impl HashBytes for Hash {
    fn get_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl HashBytes for Act {
    fn get_bytes(&self) -> Vec<u8> {
        match self {
            Act::CheckConfig(h) => {
                let mut v = vec![1u8];
                v.extendl(&h.to_vec());
                v
            },
            Act::PostShare(h, i) => {
                let mut v = vec![2u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v
            },
            Act::CombineShares(h, i, s) => {
                let mut v = vec![3u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&concat_bytes_iter(s));
                v
            },
            Act::CheckPk(h, i, pk, s) => {
                let mut v = vec![4u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&pk.to_vec());
                v.extendl(&concat_bytes_iter(s));
                v
            },
            Act::Mix(h, i, bs, pk_h) => {
                let mut v = vec![5u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&bs.to_vec());
                v.extendl(&pk_h.to_vec());
                v
            }
            Act::CheckMix(h, i, t, m, bs, pk_h) => {
                let mut v = vec![6u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&t.to_le_bytes().to_vec());
                v.extendl(&m.to_vec());
                v.extendl(&bs.to_vec());
                v.extendl(&pk_h.to_vec());
                v
            }
            Act::PartialDecrypt(h, i, bs, share_hs) => {
                let mut v = vec![7u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&bs.to_vec());
                // v.extendl(&share_h.to_vec());
                 v.extendl(&concat_bytes_iter(share_hs));
                v
            }
            Act::CombineDecryptions(h, i, ds, mix_h, shares) => {
                let mut v = vec![8u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&concat_bytes_iter(ds));
                v.extendl(&mix_h.to_vec());
                v.extendl(&concat_bytes_iter(shares));
                v
            }
            Act::CheckPlaintexts(h, i, p, ds, m, shares) => {
                let mut v = vec![9u8];
                v.extendl(&h.to_vec());
                v.extendl(&i.to_le_bytes().to_vec());
                v.extendl(&p.to_vec());
                v.extendl(&concat_bytes_iter(ds));
                v.extendl(&m.to_vec());
                v.extendl(&concat_bytes_iter(shares));
                v
            }
        }
    }
}

#[cfg(test)]
mod tests {  
    use sha2::{Sha512, Digest};
    
    #[test]
    fn test_sha512() {
        
        // create a Sha256 object
        let mut hasher = Sha512::new();

        // write input message
        hasher.update(b"hello world");

        // read hash digest and consume hasher
        let mut result = [0u8;64];
        let bytes = hasher.finalize();
        result.copy_from_slice(bytes.as_slice());
    }

}
