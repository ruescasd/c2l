use std::time::Duration;
use c2l::group::*;
use c2l::elgamal::*;
use c2l::ristretto_b::*;
use c2l::shuffler::*;

use criterion::{criterion_group, criterion_main, Criterion, SamplingMode, BenchmarkId};

fn shuffle_ristretto(n: usize) -> bool {
    let group = RistrettoGroup;
    let exp_hasher = &*group.exp_hasher();

    let sk = group.gen_key();
    let pk = PublicKey::from(&sk.public_value, &group);

    let mut es = Vec::with_capacity(10);

    for _ in 0..n {
        let plaintext = group.rnd();
        let c = pk.encrypt(&plaintext);
        es.push(c);
    }
    let seed = vec![];
    let hs = generators(es.len() + 1, &group, 0, seed);
    let shuffler = Shuffler {
        pk: &pk,
        generators: &hs,
        hasher: exp_hasher
    };
    let (e_primes, rs, perm) = shuffler.gen_shuffle(&es);
    let proof = shuffler.gen_proof(&es, &e_primes, &rs, &perm);
    // simulate computing the generators again
    let seed = vec![];
    let hs = generators(es.len() + 1, &group, 0, seed);
    let ok = shuffler.check_proof(&proof, &es, &e_primes);

    assert!(ok == true);

    ok
}

fn criterion_benchmark(c: &mut Criterion) {
    
    let mut group = c.benchmark_group("shuffle");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(60))
        .sampling_mode(SamplingMode::Flat);
    
    for size in [1000, 3000, 5000].iter() {
        group.bench_with_input(BenchmarkId::new("shuffle_ristretto", size), size, |b, &size| {
            b.iter(|| shuffle_ristretto(size));
        });
    }
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);