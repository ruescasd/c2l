use rand::rngs::OsRng;

pub trait CRng: rand::RngCore + rand::CryptoRng {}
impl CRng for OsRng {}

pub trait Rng: CRng {
    fn rng() -> Self;
}

impl Rng for OsRng {
    fn rng() -> OsRng {
        rand::rngs::OsRng
    }
}
