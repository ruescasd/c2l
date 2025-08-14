use c2l::util;
use c2l::ristretto_b::*;
use c2l::group::*;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

#[test]
fn test_size() {
    let n = 1000;
    let n_f = 1000 as f32;
    let group1 = RistrettoGroup;
    let exps1: Vec<Scalar> = (0..n).into_iter().map(|_| group1.rnd_exp()).collect();
    let mut bytes = bincode::serialize(&exps1).unwrap();
    println!("{} ristretto exps: {}, {}", n, bytes.len(), (bytes.len() as f32 / n_f));
    let elements1: Vec<RistrettoPoint> = (0..n).into_iter().map(|_| group1.rnd()).collect();
    bytes = bincode::serialize(&elements1).unwrap();
    println!("{} ristretto elements: {}, {}", n, bytes.len(), (bytes.len() as f32 / n_f));
    let es1 = util::random_ristretto_ballots(n, &group1).ciphertexts;
    bytes = bincode::serialize(&es1).unwrap();
    println!("{} ciphertexts in Ballots: {}, {}", n, bytes.len(), (bytes.len() as f32 / n_f));
    
}