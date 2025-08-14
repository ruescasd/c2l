use crate::context::Context;
use crate::cryptosystem::elgamal::{self, Ciphertext};
use crate::traits::element::GroupElement;
use crate::traits::element::Narrow;
use crate::traits::element::Widen;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use crate::traits::scalar::Narrow as NarrowS;
use crate::traits::scalar::Widen as WidenS;
use crate::utils::hash;
use crate::utils::serialization::VSerializable;
use rand::seq::SliceRandom;
use sha3::Digest;
use vser_derive::VSerializable as VSer;

use rayon::prelude::*;

pub struct Shuffler<C: Context, const W: usize> {
    h_generators: Vec<C::Element>,
    pk: elgamal::PublicKey<C>,
}

impl<C: Context, const W: usize> Shuffler<C, W> {
    pub fn new(h_generators: Vec<C::Element>, pk: elgamal::PublicKey<C>) -> Self {
        Self { h_generators, pk }
    }

    pub(crate) fn gen_private_exponents(size: usize) -> (Vec<C::Scalar>, Vec<[C::Scalar; W]>) {
        #[crate::warning("The following code is not optimized. Parallelize with rayon")]
        (0..size)
            .into_par_iter()
            .map(|_| {
                let mut rng = C::get_rng();
                (
                    C::Scalar::random(&mut rng),
                    <[C::Scalar; W]>::random(&mut rng),
                )
            })
            .collect()
    }

    #[crate::warning("The following function is not optimized. Parallelize with rayon")]
    pub fn shuffle(
        &self,
        ciphertexts: &Vec<Ciphertext<C, W>>,
        context: &[u8],
    ) -> (Vec<Ciphertext<C, W>>, ShuffleProof<C, W>) {
        let big_n = ciphertexts.len();
        let permutation = Permutation::generate::<C>(big_n);
        let permutation_data = self.apply_permutation(&permutation, ciphertexts);
        let permuted_ciphertexts = permutation_data.permuted_ciphertexts;
        let commitment_exponents = permutation_data.commitment_exponents;
        let encryption_exponents = permutation_data.encryption_exponents;
        let pedersen_commitments = permutation_data.pedersen_commitments;

        let g = C::generator();

        ///////////////// Step 1 /////////////////

        // Challenge e
        let e_n = self.challenge_e_n(ciphertexts, &permuted_ciphertexts, context);
        // the calculation of A and F is moved to Step 5

        ///////////////// Step 2 /////////////////

        // a) Bridging commitments
        let e_prime_n = permutation.apply_inverse(&e_n);
        let b_n: Vec<C::Scalar> = (0..big_n).map(|_| C::random_scalar()).collect();
        // h_1 is at index 0
        let mut big_b_previous = &self.h_generators[0];
        let mut big_b_n = vec![];
        let g_b_n: Vec<C::Element> = b_n.clone().into_par_iter().map(|b| g.exp(&b)).collect();
        for (i, g_b) in g_b_n.iter().enumerate() {
            let big_b_factor = big_b_previous.exp(e_prime_n[i]);
            // Move this exp out of the loop and parallelize
            // let big_b_i = g.exp(b);
            // let big_b_i = big_b_i.mul(&big_b_factor);
            let big_b_i = g_b.mul(&big_b_factor);
            big_b_n.push(big_b_i);
            big_b_previous = &big_b_n[i];
        }

        // b) Proof commitments
        let alpha = C::random_scalar();
        let (beta_n, epsilon_n): (Vec<C::Scalar>, Vec<C::Scalar>) = (0..big_n)
            .into_par_iter()
            .map(|_| (C::random_scalar(), C::random_scalar()))
            .collect();
        let gamma = C::random_scalar();
        let delta = C::random_scalar();
        let mut rng = C::get_rng();
        let phi = <[C::Scalar; W]>::random(&mut rng);

        // A'
        // let h_n_epsilon_n = zip_eq(self.h_generators.into_par_iter(), epsilon_n.into_par_iter());
        let h_n_epsilon_n = self
            .h_generators
            .clone()
            .into_par_iter()
            .zip(epsilon_n.clone().into_par_iter());
        let h_n_epsilon_n = h_n_epsilon_n.map(|(h, e)| h.exp(&e));
        let h_n_epsilon_n_fold = h_n_epsilon_n
            .into_par_iter()
            .reduce(C::Element::one, |acc, next| acc.mul(&next));
        // let h_n_epsilon_n_fold: C::Element = h_n_epsilon_n_fold.collect();
        let big_a_prime = g.exp(&alpha);
        let big_a_prime = big_a_prime.mul(&h_n_epsilon_n_fold);

        // B'
        // We need to start this calculation at big_b_0, which is = h_1
        // let h_1_iter = std::iter::once(&self.h_generators[0]);
        let h_1_iter = rayon::iter::once(&self.h_generators[0]);
        // the last value of big_b_0_n, B_N, is not used in this calculation, it is used later when computing big_d
        let except_last = &big_b_n[0..big_b_n.len() - 1];
        let big_b_0_n_minus_1 = h_1_iter.chain(except_last.into_par_iter());

        // chain does not play well with zip_eq, so we do this manually
        assert_eq!(except_last.len() + 1, epsilon_n.len());
        assert_eq!(epsilon_n.len(), beta_n.len());

        let big_b_n_epsilon_n = big_b_0_n_minus_1
            .into_par_iter()
            .zip(epsilon_n.clone().into_par_iter());
        let big_b_n_epsilon_n_beta_n = big_b_n_epsilon_n.zip(beta_n.clone().into_par_iter());
        let big_b_prime_n: Vec<C::Element> = big_b_n_epsilon_n_beta_n
            .into_par_iter()
            .map(|((big_b, e), beta)| {
                let g = C::generator();
                let g_beta = g.exp(&beta);
                let big_b_epsilon = big_b.exp(&e);

                g_beta.mul(&big_b_epsilon)
            })
            .collect();

        // F'
        // let w_prime_n_epsilon_n = zip_eq(permuted_ciphertexts.iter(), epsilon_n.iter());
        let w_prime_n_epsilon_n = permuted_ciphertexts
            .clone()
            .into_par_iter()
            .zip(epsilon_n.clone().into_par_iter());
        let w_prime_n_epsilon_n = w_prime_n_epsilon_n
            .into_par_iter()
            .map(|(w, e)| w.map_ref(|uv| uv.narrow_exp(&e)));
        let w_prime_n_epsilon_n = w_prime_n_epsilon_n
            .into_par_iter()
            .reduce(<[[C::Element; W]; 2]>::one, |acc, next| acc.mul(&next));
        let big_f_prime = Ciphertext::<C, W>(w_prime_n_epsilon_n);
        let big_f_prime: Ciphertext<C, W> = big_f_prime.re_encrypt(&phi.neg(), &self.pk.y);

        // C'
        let big_c_prime = g.exp(&gamma);

        // D'
        let big_d_prime = g.exp(&delta);

        let commitments = ShuffleCommitments::new(
            big_b_n,
            big_a_prime,
            big_b_prime_n,
            big_c_prime,
            big_d_prime,
            big_f_prime,
            pedersen_commitments,
        );

        ///////////////// Step 3 /////////////////

        // Challenge v
        let (input, dsts) = self.challenge_input_v(&commitments, context);
        let input: Vec<&[u8]> = input.iter().map(|v| v.as_slice()).collect();
        let v = C::G::hash_to_scalar(&input, &dsts);

        ///////////////// Step 4 /////////////////

        // a
        let r_n_e_prime_n = zip_eq(commitment_exponents.iter(), e_prime_n.iter());
        let r_n_e_prime_n = r_n_e_prime_n.map(|(r, e)| r.mul(e));
        let a = r_n_e_prime_n.fold(C::Scalar::zero(), |acc, next| acc.add(&next));

        // c
        let c = commitment_exponents
            .iter()
            .fold(C::Scalar::zero(), |acc, next| acc.add(next));

        // f
        let s_n_e_n = zip_eq(encryption_exponents.iter(), e_n.iter());
        let s_n_e_n = s_n_e_n.map(|(s, e)| s.narrow_mul(e));
        let f = s_n_e_n.fold(<[C::Scalar; W]>::zero(), |acc, next| acc.add(&next));

        // d_n
        // "sets d1 = b1 and computes di = bi + e′i*di−1 for i ∈ [N]"
        // This means we start the computation at i = 1 (which is i = 2 in a 1-based index)
        let mut d_n = vec![b_n[0].clone()];
        #[crate::warning("Figure out how this skip(1) behaves")]
        for (i, b) in b_n.iter().enumerate().skip(1) {
            let e_prime_d = e_prime_n[i].mul(&d_n[i - 1]);
            let sum = b.add(&e_prime_d);
            d_n.push(sum);
        }
        // d
        let d = &d_n[d_n.len() - 1];

        // k_a
        let k_a = v.mul(&a).add(&alpha);

        // k_b
        let b_n_beta_n = zip_eq(b_n.iter(), beta_n.iter());
        let k_b_n: Vec<C::Scalar> = b_n_beta_n
            .map(|(b, beta)| {
                let vb = v.mul(b);
                vb.add(beta)
            })
            .collect();

        // k_e_n
        let e_prime_n_epsilon_n = zip_eq(e_prime_n.iter(), epsilon_n.iter());
        let k_e_n: Vec<C::Scalar> = e_prime_n_epsilon_n
            .map(|(e, epsilon)| {
                let ve = v.mul(e);
                ve.add(epsilon)
            })
            .collect();

        // k_c
        let k_c = v.mul(&c).add(&gamma);

        // k_d
        let k_d = v.mul(d).add(&delta);

        // k_f
        let k_f = v.widen_mul(&f).add(&phi);

        let responses = Responses::<C, W>::new(k_a, k_b_n, k_c, k_d, k_e_n, k_f);
        let proof = ShuffleProof::new(commitments, responses);

        (permuted_ciphertexts, proof)
    }

    #[crate::warning("The following function is not optimized. Parallelize with rayon")]
    pub fn verify(
        &self,
        ciphertexts: &Vec<Ciphertext<C, W>>,
        permuted_ciphertexts: &Vec<Ciphertext<C, W>>,
        proof: &ShuffleProof<C, W>,
        context: &[u8],
    ) -> bool {
        let commitments = &proof.commitments;
        let responses = &proof.responses;
        let g = C::generator();

        let e_n = self.challenge_e_n(ciphertexts, permuted_ciphertexts, context);
        let (input, dsts) = self.challenge_input_v(commitments, context);
        let input: Vec<&[u8]> = input.iter().map(|v| v.as_slice()).collect();
        let v = C::G::hash_to_scalar(&input, &dsts);

        ///////////////// Step 5 /////////////////

        // A (comes from Step 1 in evs)
        let e_n_u_n = zip_eq(e_n.iter(), commitments.u_n.iter());
        let big_a_n = e_n_u_n.map(|(e, u)| u.exp(e));
        let big_a: C::Element = big_a_n.fold(C::Element::one(), |acc, next| acc.mul(&next));

        // F (comes from Step 1 in evs)
        let e_n_w_n = zip_eq(e_n.iter(), ciphertexts.iter());
        let big_f_n = e_n_w_n.map(|(e, w)| w.map_ref(|uv| uv.narrow_exp(e)));
        // let big_f_n = e_n_w_n.map(|(e, w)| array::from_fn(|i| w.0[i].narrow_exp(&e)));
        let one = <[[C::Element; W]; 2]>::one();
        let big_f: [[C::Element; W]; 2] = big_f_n.fold(one, |acc, next| acc.mul(&next));

        // C
        let u_n_fold = commitments
            .u_n
            .iter()
            .fold(C::Element::one(), |acc, next| acc.mul(next));
        let h_n_fold = self
            .h_generators
            .iter()
            .fold(C::Element::one(), |acc, next| acc.mul(next));
        let big_c = u_n_fold.mul(&h_n_fold.inv());

        // D
        let e_n_fold = e_n.iter().fold(C::Scalar::one(), |acc, next| acc.mul(next));
        let h1_e_n_fold = self.h_generators[0].exp(&e_n_fold);
        // this is B_N
        let big_b_last = &commitments.big_b_n[commitments.big_b_n.len() - 1];
        let big_d = big_b_last.mul(&h1_e_n_fold.inv());

        // B_0
        let big_b_0 = &self.h_generators[0];

        ////// Verification 1 //////

        let h_n_k_e_n = zip_eq(self.h_generators.iter(), responses.k_e_n.iter());
        let h_n_k_e_n = h_n_k_e_n.map(|(h, k)| h.exp(k));
        let h_n_k_e_n_fold = h_n_k_e_n.fold(C::Element::one(), |acc, next| acc.mul(&next));
        let g_k_a = g.exp(&responses.k_a);
        let lhs_1 = big_a.exp(&v).mul(&commitments.big_a_prime);
        let rhs_1 = g_k_a.mul(&h_n_k_e_n_fold);

        ////// Verification 2 //////

        // We need to start this calculation at big_b_0, which is = h_1
        let h_1_iter = std::iter::once(big_b_0);
        // the last value of big_b_0_n, B_N, is not used in this calculation, it is used later when computing big_d
        let big_b_n = &commitments.big_b_n;
        let except_last = &big_b_n[0..big_b_n.len() - 1];
        let big_b_0_n_minus_1 = h_1_iter.chain(except_last);

        // chain does not play well with zip_eq, so we do this manually
        assert_eq!(except_last.len() + 1, responses.k_e_n.len());
        assert_eq!(responses.k_e_n.len(), responses.k_b_n.len());
        let big_b_0_n_minus_1_k_e_n = big_b_0_n_minus_1.zip(responses.k_e_n.iter());
        let big_b_0_n_minus_1_k_e_n_k_b_n = big_b_0_n_minus_1_k_e_n.zip(responses.k_b_n.iter());

        let rhs_2: Vec<C::Element> = big_b_0_n_minus_1_k_e_n_k_b_n
            .map(|((b, k_e), k_b)| {
                let g = C::generator();
                let b_k_e = b.exp(k_e);
                let g_k_b = g.exp(k_b);

                g_k_b.mul(&b_k_e)
            })
            .collect();

        let big_b_prime_n = &commitments.big_b_prime_n;
        let big_b_n_big_b_prime_n = zip_eq(big_b_n.iter(), big_b_prime_n.iter());
        let lhs_2: Vec<C::Element> = big_b_n_big_b_prime_n
            .map(|(big_b, big_b_prime)| {
                let big_b_v = big_b.exp(&v);
                big_b_v.mul(big_b_prime)
            })
            .collect();

        ////// Verification 3 //////

        let big_c_v = big_c.exp(&v);
        let lhs_3 = big_c_v.mul(&commitments.big_c_prime);
        let rhs_3 = g.exp(&responses.k_c);

        ////// Verification 4 //////

        let big_d_v = big_d.exp(&v);
        let lhs_4 = big_d_v.mul(&commitments.big_d_prime);
        let rhs_4 = g.exp(&responses.k_d);

        ////// Verification 5 //////

        let big_f_prime = &commitments.big_f_prime;
        let big_f_v = big_f.map(|uv| uv.narrow_exp(&v));
        let lhs_5 = big_f_v.mul(&big_f_prime.0);

        let w_prime_n = permuted_ciphertexts;
        let w_prime_n_k_e_n = zip_eq(w_prime_n.iter(), responses.k_e_n.iter());
        let w_prime_n_k_e_n = w_prime_n_k_e_n.map(|(w, k)| w.map_ref(|uv| uv.narrow_exp(k)));
        let one = <[[C::Element; W]; 2]>::one();
        let w_prime_n_k_e_n_fold = w_prime_n_k_e_n.fold(one, |acc, next| acc.mul(&next));
        let g = C::generator();
        let one = [g, self.pk.y.clone()].map(|gy| gy.widen_exp(&responses.k_f.neg()));
        let rhs_5 = one.mul(&w_prime_n_k_e_n_fold);

        lhs_1 == rhs_1 && lhs_2 == rhs_2 && lhs_3 == rhs_3 && lhs_4 == rhs_4 && lhs_5 == rhs_5
    }

    pub(crate) fn apply_permutation(
        &self,
        permutation: &Permutation,
        ciphertexts: &[Ciphertext<C, W>],
    ) -> PermutationData<C, W> {
        let (r_n, s_n) = Self::gen_private_exponents(ciphertexts.len());

        let r_permuted = permutation.apply(&r_n);
        let h_permuted = permutation.apply(&self.h_generators);
        let w_permuted = permutation.apply_inverse(ciphertexts);
        let s_permuted = permutation.apply_inverse(&s_n);

        // let r_h_permuted = zip_eq(r_permuted.iter(), h_permuted.iter());
        let r_h_permuted = r_permuted.into_par_iter().zip(h_permuted.into_par_iter());
        #[crate::warning("The following code is not optimized. Parallelize with rayon")]
        let u_n: Vec<C::Element> = r_h_permuted
            .into_par_iter()
            .map(|(r, h)| {
                let g = C::generator();
                let g_r = g.exp(r);
                g_r.mul(h)
            })
            .collect();

        // let s_w_permuted = zip_eq(w_permuted.iter(), s_permuted.iter());
        let s_w_permuted = w_permuted.into_par_iter().zip(s_permuted.into_par_iter());

        #[crate::warning("The following code is not optimized. Parallelize with rayon")]
        let w_prime_n: Vec<Ciphertext<C, W>> = s_w_permuted
            .into_par_iter()
            .map(|(c, s)| c.re_encrypt(s, &self.pk.y))
            .collect();

        PermutationData::new(r_n, s_n, u_n, w_prime_n)
    }

    #[crate::warning("Challenge inputs are incomplete.")]
    const DS_TAGS_CHALLENGE_E: [&[u8]; 4] = [
        b"shuffle_proof_challenge_e_context",
        b"pk",
        b"w_n",
        b"w_prime_n",
    ];

    fn challenge_e_n(
        &self,
        w_n: &Vec<Ciphertext<C, W>>,
        w_prime_n: &Vec<Ciphertext<C, W>>,
        context: &[u8],
    ) -> Vec<C::Scalar> {
        #[crate::warning("Serialization of vectors is serial")]
        let a = [context.to_vec(), self.pk.ser(), w_n.ser(), w_prime_n.ser()];
        let input: Vec<&[u8]> = a.iter().map(|v| v.as_slice()).collect();

        let mut hasher = C::get_hasher();
        hash::update_hasher(&mut hasher, &input, &Self::DS_TAGS_CHALLENGE_E);
        #[crate::warning("Verify that this double hashing set up is ok")]
        let bytes = hasher.finalize();
        let mut ret = vec![];

        #[crate::warning("The following code is not optimized. Parallelize with rayon")]
        for i in 0..w_n.len() {
            let prefix = bytes.clone();
            let inputs: &[&[u8]] = &[prefix.as_slice(), &i.to_be_bytes()];
            let ds_tags: &[&[u8]; 2] = &[b"prefix", b"shuffle_proof_challenge_e_counter"];
            let scalar = C::G::hash_to_scalar(inputs, ds_tags);
            ret.push(scalar);
        }

        ret
    }

    #[crate::warning("Challenge inputs are incomplete.")]
    const DS_TAGS_CHALLENGE_V: [&[u8]; 7] = [
        b"shuffle_challenge_input_v_context",
        b"big_b_n",
        b"big_a_prime",
        b"big_b_prime_n",
        b"big_c_prime",
        b"big_d_prime",
        b"big_f_prime_n",
    ];

    fn challenge_input_v(
        &self,
        commitments: &ShuffleCommitments<C, W>,
        context: &[u8],
    ) -> ([Vec<u8>; 7], [&'static [u8]; 7]) {
        #[crate::warning("Serialization of vectors is serial")]
        let a = [
            context.to_vec(),
            commitments.big_b_n.ser(),
            commitments.big_a_prime.ser(),
            commitments.big_b_prime_n.ser(),
            commitments.big_c_prime.ser(),
            commitments.big_d_prime.ser(),
            commitments.big_f_prime.ser(),
        ];
        (a, Self::DS_TAGS_CHALLENGE_V)
    }
}

pub(crate) struct PermutationData<C: Context, const W: usize> {
    commitment_exponents: Vec<C::Scalar>,
    encryption_exponents: Vec<[C::Scalar; W]>,
    pedersen_commitments: Vec<C::Element>,
    permuted_ciphertexts: Vec<Ciphertext<C, W>>,
}
impl<C: Context, const W: usize> PermutationData<C, W> {
    pub fn new(
        commitment_exponents: Vec<C::Scalar>,
        encryption_exponents: Vec<[C::Scalar; W]>,
        pedersen_commitments: Vec<C::Element>,
        permuted_ciphertexts: Vec<Ciphertext<C, W>>,
    ) -> Self {
        Self {
            commitment_exponents,
            encryption_exponents,
            pedersen_commitments,
            permuted_ciphertexts,
        }
    }
}

#[derive(Debug, VSer)]
pub struct ShuffleProof<C: Context, const W: usize> {
    pub commitments: ShuffleCommitments<C, W>,
    pub responses: Responses<C, W>,
}
impl<C: Context, const W: usize> ShuffleProof<C, W> {
    pub fn new(commitments: ShuffleCommitments<C, W>, responses: Responses<C, W>) -> Self {
        Self {
            commitments,
            responses,
        }
    }
}

#[derive(Debug, VSer)]
pub struct ShuffleCommitments<C: Context, const W: usize> {
    big_b_n: Vec<C::Element>,
    big_a_prime: C::Element,
    big_b_prime_n: Vec<C::Element>,
    big_c_prime: C::Element,
    big_d_prime: C::Element,
    big_f_prime: Ciphertext<C, W>,
    // pedersen commitments
    u_n: Vec<C::Element>,
}
impl<C: Context, const W: usize> ShuffleCommitments<C, W> {
    pub fn new(
        big_b_n: Vec<C::Element>,
        big_a_prime: C::Element,
        big_b_prime_n: Vec<C::Element>,
        big_c_prime: C::Element,
        big_d_prime: C::Element,
        big_f_prime: Ciphertext<C, W>,
        u_n: Vec<C::Element>,
    ) -> Self {
        Self {
            big_b_n,
            big_a_prime,
            big_b_prime_n,
            big_c_prime,
            big_d_prime,
            big_f_prime,
            u_n,
        }
    }
}

#[derive(Debug, VSer)]
pub struct Responses<C: Context, const W: usize> {
    pub k_a: C::Scalar,
    pub k_b_n: Vec<C::Scalar>,
    pub k_c: C::Scalar,
    pub k_d: C::Scalar,
    pub k_e_n: Vec<C::Scalar>,
    pub k_f: [C::Scalar; W],
}
impl<C: Context, const W: usize> Responses<C, W> {
    pub fn new(
        k_a: C::Scalar,
        k_b_n: Vec<C::Scalar>,
        k_c: C::Scalar,
        k_d: C::Scalar,
        k_e_n: Vec<C::Scalar>,
        k_f: [C::Scalar; W],
    ) -> Self {
        Self {
            k_a,
            k_b_n,
            k_c,
            k_d,
            k_e_n,
            k_f,
        }
    }
}

pub(crate) struct Permutation {
    pub permutation: Vec<usize>,
    pub inverse: Vec<usize>,
}
impl Permutation {
    // "The resulting permutation is picked uniformly from the set of all possible
    // permutations." https://rust-random.github.io/rand/rand/seq/trait.SliceRandom.html
    pub(crate) fn generate<C: Context>(size: usize) -> Self {
        let mut rng = C::get_rng();

        let mut permutation: Vec<usize> = (0..size).collect();
        permutation.shuffle(&mut rng);

        let mut inverse = vec![0usize; size];

        for (i, v) in permutation.iter().enumerate() {
            inverse[*v] = i;
        }

        Self {
            permutation,
            inverse,
        }
    }

    pub(crate) fn len(&self) -> usize {
        // does not matter which field we choose, they are of equal size
        self.permutation.len()
    }

    pub(crate) fn apply<'a, T>(&self, target: &'a [T]) -> Vec<&'a T> {
        let size = self.permutation.len();

        // This is necessary to safely get a placeholder reference below.
        if target.is_empty() {
            return vec![];
        }

        // We need a valid reference to fill the vector initially.
        // We can just use the first element of the target slice (which is non-empty)
        let placeholder_ref = &target[0];
        let mut permuted = vec![placeholder_ref; size];

        for (i, v) in target.iter().enumerate() {
            permuted[self.permutation[i]] = v;
        }

        permuted
    }

    pub(crate) fn apply_inverse<'a, T>(&self, target: &'a [T]) -> Vec<&'a T> {
        let size = self.inverse.len();

        // This is necessary to safely get a placeholder reference below.
        if target.is_empty() {
            return vec![];
        }

        // We need a valid reference to fill the vector initially.
        // We can just use the first element of the target slice (which is non-empty)
        let placeholder_ref = &target[0];
        let mut permuted = vec![placeholder_ref; size];

        for (i, v) in target.iter().enumerate() {
            permuted[self.inverse[i]] = v;
        }

        permuted
    }
}

use std::iter::Zip;

#[crate::warning("Probably remove this, it is incompatible with rayon.")]
fn zip_eq<I1, I2>(iter1: I1, iter2: I2) -> Zip<I1, I2>
where
    I1: ExactSizeIterator,
    I2: ExactSizeIterator,
{
    // The core logic: check the lengths before zipping.
    if iter1.len() != iter2.len() {
        panic!("Called zip_eq with iterators of different sizes")
    } else {
        iter1.zip(iter2)
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use crate::context::Context;
    use crate::context::P256Ctx as PCtx;
    use crate::context::RistrettoCtx as RCtx;
    use crate::cryptosystem::elgamal::Ciphertext;
    use crate::cryptosystem::elgamal::KeyPair;
    use crate::cryptosystem::elgamal::PublicKey;
    use crate::traits::group::CryptoGroup;
    use crate::zkp::shuffle::Shuffler;

    #[test]
    fn test_shuffle_ristretto() {
        test_shuffle::<RCtx, 2>();
        test_shuffle::<RCtx, 3>();
        test_shuffle::<RCtx, 4>();
        test_shuffle::<RCtx, 5>();
    }

    #[test]
    fn test_shuffle_p256() {
        test_shuffle::<PCtx, 2>();
        test_shuffle::<PCtx, 3>();
        test_shuffle::<PCtx, 4>();
        test_shuffle::<PCtx, 5>();
    }

    #[test]
    fn test_shuffle_label_ristretto() {
        test_shuffle_label::<RCtx>();
    }

    #[test]
    fn test_shuffle_label_p256() {
        test_shuffle_label::<PCtx>();
    }

    fn test_shuffle<C: Context, const W: usize>() {
        let count = 10;
        let keypair: KeyPair<C> = KeyPair::generate();

        let messages: Vec<[C::Element; W]> = (0..count)
            .map(|_| array::from_fn(|_| C::random_element()))
            .collect();

        let ciphertexts: Vec<Ciphertext<C, W>> =
            messages.iter().map(|m| keypair.encrypt(m)).collect();

        let pk: PublicKey<C> = PublicKey::new(keypair.pkey.clone());
        let generators = C::G::ind_generators(count, &vec![]);
        let shuffler = Shuffler::<C, W>::new(generators, pk);

        let (pciphertexts, proof) = shuffler.shuffle(&ciphertexts, &vec![]);
        let ok = shuffler.verify(&ciphertexts, &pciphertexts, &proof, &vec![]);

        assert!(ok);
    }

    fn test_shuffle_label<C: Context>() {
        const W: usize = 3;
        let count = 10;
        let keypair: KeyPair<C> = KeyPair::generate();

        let messages: Vec<[C::Element; W]> = (0..count)
            .map(|_| array::from_fn(|_| C::random_element()))
            .collect();

        let ciphertexts: Vec<Ciphertext<C, W>> =
            messages.iter().map(|m| keypair.encrypt(m)).collect();

        let pk: PublicKey<C> = PublicKey::new(keypair.pkey.clone());
        let generators = C::G::ind_generators(count, &vec![]);
        let shuffler = Shuffler::<C, W>::new(generators, pk);

        let (pciphertexts, proof) = shuffler.shuffle(&ciphertexts, &vec![1u8]);
        let ok = shuffler.verify(&ciphertexts, &pciphertexts, &proof, &vec![2u8]);

        assert!(!ok);
    }
}
