use sha3::digest::{ExtendableOutput, FixedOutput};
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

pub trait Hasher: Digest + FixedOutput {
    fn hasher() -> Self;
}

pub trait XofHasher: ExtendableOutput {
    fn xof_hasher() -> Self;
}

impl XofHasher for Shake256 {
    fn xof_hasher() -> Self {
        Shake256::default()
    }
}

impl Hasher for Sha3_512 {
    fn hasher() -> Self {
        Sha3_512::new()
    }
}

impl Hasher for Sha3_256 {
    fn hasher() -> Self {
        Sha3_256::new()
    }
}

pub type Hasher512 = Sha3_512;
pub type Hasher256 = Sha3_256;

pub struct HashToInput<'a> {
    pub slices: &'a [&'a [u8]],
    pub ds_tags: &'a [&'a [u8]],
}

pub fn update_hasher(hasher: &mut impl Digest, data_slices: &[&[u8]], ds_tags: &[&[u8]]) {
    for (i, slice) in data_slices.iter().enumerate() {
        hasher.update(slice);
        if ds_tags.len() > i {
            hasher.update(ds_tags[i]);
        }
    }
}
