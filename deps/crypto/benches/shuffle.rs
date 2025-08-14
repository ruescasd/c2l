#![feature(test)]

extern crate test;

use std::array;
use test::black_box;
use test::Bencher;

use crypto::context::Context;
// use crypto::context::P256Ctx as PCtx;
use crypto::context::RistrettoCtx as RCtx;
use crypto::cryptosystem::elgamal::Ciphertext;
use crypto::cryptosystem::elgamal::KeyPair;
use crypto::cryptosystem::elgamal::PublicKey;
use crypto::traits::group::CryptoGroup;
use crypto::zkp::shuffle::Shuffler;

#[bench]
fn bench_shuffle_prove_ristretto(b: &mut Bencher) {
    bench_shuffle_prove::<RCtx>(b);
}

#[bench]
fn bench_shuffle_verify_ristretto(b: &mut Bencher) {
    bench_shuffle_verify::<RCtx>(b);
}
/*
// ----- Benchmarks for P256 -----
#[bench]
fn bench_shuffle_prove_p256(b: &mut Bencher) {
    bench_shuffle_prove::<PCtx>(b);
}

#[bench]
fn bench_shuffle_verify_p256(b: &mut Bencher) {
    bench_shuffle_verify::<PCtx>(b);
}*/

/// Generic benchmark for the shuffle proof generation (`shuffle` function).
fn bench_shuffle_prove<C: Context>(b: &mut Bencher) {
    const W: usize = 3;
    let count = 100;
    let keypair: KeyPair<C> = KeyPair::generate();
    let messages: Vec<[C::Element; W]> = (0..count)
        .map(|_| array::from_fn(|_| C::random_element()))
        .collect();
    let ciphertexts: Vec<Ciphertext<C, W>> = messages.iter().map(|m| keypair.encrypt(m)).collect();
    let pk: PublicKey<C> = PublicKey::new(keypair.pkey.clone());
    let generators = C::G::ind_generators(count, &vec![]);
    let shuffler = Shuffler::<C, W>::new(generators, pk);

    b.iter(|| {
        let (_pciphertexts, _proof) = black_box(shuffler.shuffle(&ciphertexts, &vec![]));
    });
}

fn bench_shuffle_verify<C: Context>(b: &mut Bencher) {
    const W: usize = 3;
    let count = 100;
    let keypair: KeyPair<C> = KeyPair::generate();
    let messages: Vec<[C::Element; W]> = (0..count)
        .map(|_| array::from_fn(|_| C::random_element()))
        .collect();
    let ciphertexts: Vec<Ciphertext<C, W>> = messages.iter().map(|m| keypair.encrypt(m)).collect();
    let pk: PublicKey<C> = PublicKey::new(keypair.pkey.clone());
    let generators = C::G::ind_generators(count, &vec![]);
    let shuffler = Shuffler::<C, W>::new(generators, pk);

    let (pciphertexts, proof) = shuffler.shuffle(&ciphertexts, &vec![]);

    b.iter(|| {
        let ok = black_box(shuffler.verify(&ciphertexts, &pciphertexts, &proof, &vec![]));
        assert!(ok);
    });
}
