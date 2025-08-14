use crate::traits::element::GroupElement;
use crate::traits::group::CryptoGroup;
use crate::traits::scalar::GroupScalar;
use js_sys::Array as JsArray;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;

use crate::context::Context;
use crate::utils::serialization::VSerializable;
use vser_derive::VSerializable as VSer;

use crate::traits::element::Narrow;
use crate::traits::scalar::Widen as WidenS;

// Commitment \in (G x G)^3
type Commitment<C> = [[<C as Context>::Element; 2]; 3];
// Response \in Z^4
type Response<C> = [<C as Context>::Scalar; 4];

#[derive(Debug, VSer)]
pub struct BitProof<C: Context> {
    pub commitment: Commitment<C>,
    pub response: Response<C>,
}

impl<C: Context> BitProof<C> {
    pub fn new(commitment: Commitment<C>, response: Response<C>) -> Self {
        BitProof {
            commitment,
            response,
        }
    }
}

// big_g, big_h and big_c are fixed values, which we pass in for convenience
// In an alternate implementation, hom would be a trait implemented by a struct with
// these fixed values
fn hom<C: Context>(
    big_g: &[C::Element; 2],
    big_h: &[C::Element; 2],
    big_c: &[C::Element; 2],
    b: &C::Scalar,
    r: &C::Scalar,
    s: &C::Scalar,
    t: &C::Scalar,
) -> [[C::Element; 2]; 3] {
    // H^bG^r
    let h_pow_b = big_h.narrow_exp(b);
    let g_pow_r = big_g.narrow_exp(r);
    let prod = h_pow_b.mul(&g_pow_r);
    // C^bG^s
    let c_pow_b = big_c.narrow_exp(b);
    let g_pow_s = big_g.narrow_exp(s);
    let cb_gs = c_pow_b.mul(&g_pow_s);
    // G^t
    let g_pow_t = big_g.narrow_exp(t);

    [prod, cb_gs, g_pow_t]
}

pub fn prove<C: Context>(
    bit: &C::Scalar,
    r_real: &C::Scalar,
    s_real: &C::Scalar,
    ciphertext: &[C::Element; 2],
    c_prime: &[C::Element; 2],
    y: &C::Element,
) -> BitProof<C> {
    let generator = C::generator();
    let identity = C::Element::one();

    // G=(g,y)
    // H=(1,g)
    let big_g = [generator, y.clone()];
    let big_h = [identity, C::generator()];

    // generate random A = (r,s,t), we use b as the real value
    let b = bit.clone();
    let r = C::random_scalar();
    let s = C::random_scalar();
    let t = C::random_scalar();

    // A = (b,r,s,t). b,r,s,t is randomly generated
    let big_a = [bit.clone(), r.clone(), s.clone(), t.clone()];
    // commitment: compute B=f(A)
    let big_b = hom::<C>(&big_g, &big_h, ciphertext, bit, &r, &s, &t);

    // Challenge: v
    let v: C::Scalar = C::G::hash_to_scalar(
        &[
            &big_b.ser(),
            // include the statement in the hash
            &ciphertext.ser(),
            &c_prime.ser(),
        ],
        &[b"bit_zkp_commitment", b"elgamal_ciphertext", b"c_prime"],
    );

    // X=(b,r,s,t) is a preimage.
    let t_real = r_real.mul(&b.sub(&C::Scalar::one()));
    let t_real = t_real.add(s_real);
    // let t_real = r.mul(&b).sub(&s);
    let big_x = [bit.clone(), r_real.clone(), s_real.clone(), t_real];
    let vx = v.widen_mul(&big_x);

    // response D=vX+A
    let big_d = vx.add(&big_a);

    BitProof::<C>::new(big_b, big_d)
}

pub fn verify<C: Context>(
    proof: &BitProof<C>,
    ciphertext: &[C::Element; 2],
    c_prime: &[C::Element; 2],
    y: &C::Element,
) -> bool {
    let generator = C::generator();
    let identity = C::Element::one();

    // G=(g,y)
    // H=(1,g)
    let big_g = [generator, y.clone()];
    let big_h = [identity, C::generator()];

    // Challenge: v
    let v: C::Scalar = C::G::hash_to_scalar(
        &[
            &proof.commitment.ser(),
            // include the statement in the hash
            &ciphertext.ser(),
            &c_prime.ser(),
        ],
        &[b"bit_zkp_commitment", b"elgamal_ciphertext", b"c_prime"],
    );

    // C''=C'/C
    let c_inv = ciphertext.inv();
    let c_prime_2 = c_prime.mul(&c_inv);
    // Y=(C,C',C'')
    let big_y = [ciphertext.clone(), c_prime.clone(), c_prime_2];

    // response D=vX+A
    let resp: &[C::Scalar; 4] = &proof.response;

    // Check: Y^vB=f(D)
    let y_pow_v = big_y.map(|x| x.narrow_exp(&v));
    let lhs = y_pow_v.mul(&proof.commitment);

    let rhs = hom::<C>(
        &big_g, &big_h, ciphertext, &resp[0], &resp[1], &resp[2], &resp[3],
    );

    lhs.eq(&rhs)
}

mod types {
    use super::*;
    pub(crate) type CtxElement<C> = <C as Context>::Element;
    pub(crate) type CtxScalar<C> = <C as Context>::Scalar;
    pub(crate) type CtxGroup<C> = <C as Context>::G;
}

#[wasm_bindgen]
pub fn benchmark_prove(iterations: u32) -> JsArray {
    use crate::context::Context;
    use crate::context::P256Ctx as CtxP;
    use crate::context::P256Ctx as CtxR;
    use crate::cryptosystem::elgamal::KeyPair;
    use crate::traits::scalar::GroupScalar;
    use crate::traits::GroupElement;
    use rand::Rng;
    use types::*;
    use web_time::Instant;

    if iterations == 0 {
        let results = JsArray::new();
        results.push(&JsValue::from_f64(0.0));
        results.push(&JsValue::from_f64(0.0));
        return results;
    }

    let mut rng = CtxR::get_rng();

    // Ristretto Benchmark
    let g_ristretto = CtxR::generator();
    let keypair_ristretto = KeyPair::<CtxR>::generate();
    let mut total_duration_ristretto = 0.0;

    for _ in 0..iterations {
        let b = if rng.gen_bool(0.5) {
            CtxScalar::<CtxP>::one()
        } else {
            CtxScalar::<CtxP>::zero()
        };

        let b_2 = [b; 2];
        let message = g_ristretto.exp(&b);

        let start_time = Instant::now();
        let r = CtxR::random_scalar();
        let gr = g_ristretto.exp(&r);
        let hr = keypair_ristretto.pkey.exp(&r);
        let mhr = hr.mul(&message);
        let c = [gr, mhr];

        let big_g = [g_ristretto, keypair_ristretto.pkey];
        let s = CtxR::random_scalar();
        let s_2 = [s; 2];
        let c_pow_b = c.exp(&b_2);
        let g_pow_s = big_g.exp(&s_2);
        let c_prime = c_pow_b.mul(&g_pow_s);

        let proof: BitProof<CtxR> = prove(&b, &r, &s, &c, &c_prime, &keypair_ristretto.pkey);
        let duration = start_time.elapsed();
        assert!(verify(&proof, &c, &c_prime, &keypair_ristretto.pkey));
        total_duration_ristretto += duration.as_secs_f64() * 1000.0; // Convert to milliseconds
    }
    let avg_ristretto_time = total_duration_ristretto / iterations as f64;

    // P256 Benchmark
    let mut rng = CtxP::get_rng();
    let g_p256 = CtxP::generator();
    let keypair_p256 = KeyPair::<CtxP>::generate();
    let mut total_duration_p256 = 0.0;

    for _ in 0..iterations {
        let b = if rng.gen_bool(0.5) {
            CtxScalar::<CtxP>::one()
        } else {
            CtxScalar::<CtxP>::zero()
        };

        let b_2 = [b; 2];
        let message = g_p256.exp(&b);

        let start_time = Instant::now();
        let r = CtxP::random_scalar();
        let gr = g_p256.exp(&r);
        let hr = keypair_p256.pkey.exp(&r);
        let mhr = hr.mul(&message);
        let c = [gr, mhr];

        let big_g = [g_p256, keypair_p256.pkey];
        let s = CtxP::random_scalar();
        let s_2 = [s; 2];
        let c_pow_b = c.exp(&b_2);
        let g_pow_s = big_g.exp(&s_2);
        let c_prime = c_pow_b.mul(&g_pow_s);

        let proof: BitProof<CtxP> = prove(&b, &r, &s, &c, &c_prime, &keypair_p256.pkey);
        let duration = start_time.elapsed();
        assert!(verify(&proof, &c, &c_prime, &keypair_p256.pkey));
        total_duration_p256 += duration.as_secs_f64() * 1000.0; // Convert to milliseconds
    }
    let avg_p256_time = total_duration_p256 / iterations as f64;

    let results = JsArray::new();
    results.push(&JsValue::from_f64(avg_ristretto_time));
    results.push(&JsValue::from_f64(avg_p256_time));
    results
}

#[cfg(test)]
mod tests {
    use super::types::*;
    use super::*;
    use crate::context::Context;
    use crate::context::RistrettoCtx as RCtx;
    use crate::context::RistrettoCtx as PCtx;
    use crate::cryptosystem::elgamal::KeyPair;
    use crate::utils::serialization::{FDeserializable, FSerializable};
    use rand::Rng;

    #[test]
    fn test_bit_zkp_prove_ristretto() {
        test_bit_zkp_prove::<RCtx>();
    }

    #[test]
    fn test_bit_zkp_prove_p256() {
        test_bit_zkp_prove::<PCtx>();
    }

    fn test_bit_zkp_prove<Ctx: Context>() {
        let g = Ctx::generator();
        let keypair = KeyPair::<Ctx>::generate();
        let mut rng = Ctx::get_rng();

        for _ in 0..5 {
            let b = if rng.gen_bool(0.5) {
                CtxScalar::<Ctx>::one()
            } else {
                CtxScalar::<Ctx>::zero()
            };

            // let b_2 = [b.clone(); 2];
            let message = g.exp(&b);

            let r = Ctx::random_scalar();
            let gr = g.exp(&r);
            let hr = keypair.pkey.exp(&r);
            let mhr = hr.mul(&message);
            let c = [gr, mhr];

            let big_g = [g.clone(), keypair.pkey.clone()];
            let s = Ctx::random_scalar();
            // let s_2 = [s.clone(); 2];
            let c_pow_b = c.narrow_exp(&b);
            let g_pow_s = big_g.narrow_exp(&s);
            let c_prime = c_pow_b.mul(&g_pow_s);

            let proof: BitProof<Ctx> = prove(&b, &r, &s, &c, &c_prime, &keypair.pkey);
            let proof_bytes = proof.ser_f();
            assert_eq!(proof_bytes.len(), BitProof::<Ctx>::size_bytes());

            let proof = BitProof::<Ctx>::deser_f(&proof_bytes).unwrap();

            let ok = verify(&proof, &c, &c_prime, &keypair.pkey);

            assert!(ok);
        }
    }
}

/*

r       r2              r + r2
b       b2              b + b2                  g(r+r2)(b + b2) = rb + rb2 + r2b + r2b2

g^rb    g^r2b2          g^rb + r2b2

G=(g,y)
H=(1,g)

r1b + s1 + r2b + s2 = (r1+r2)b + (s1 + s2)

H^bG^r is ElGamal ciphertext of g^b, where r is from the exponents of g, and not G. Similarly, b is is bits (bk,...,b0) in the exponents of g.

C=H^bG^r            (1^b * g^r, g^b * h^r)
C'=C^bG^s        (g^rb, g^b^2 h^rb) * (g^s, h^s) = g^rb + s, g^b^2 h^rb + s
=H^(b^2)G^(rb+s)

g^rb + s / g^r = rb - r + s = r(b - 1) + s

then C' is an encryption of b^2 (element-wise), so we require that

C''=C'/C=G^t

with t=rb-s to show that b^2=b.

Consider the map

f(b,r,s,t)=( H^bG^r, C^bG^s, G^t )

Note that Y=(C,C',C'') is an image, and X=(b,r,s,t) is a preimage.

We have a homomorphism f and all we need is a single general Schnorr proof!

Y=f(X)

Commitment: Pick A (r,s,t) randomly and compute B=f(A) with the real value of b.

Challenge: v

Response: D=vX+A

Check: Y^vB=f(D)

The public statement is (C, C')


*/

/*
For any fixed H, G, C, H

f(b,r,s,t)=(H^bG^r, C^bG^s, G^t)

= (..., C^bG^s, ...)

= ( (H^bG^r)^b * G^s)

= (1, g^b)^b * (g^r, y^r)^b * (g^s, y^s)

= (1^b, g^b^2) * (g^rb, y^rb) * (g^s, y^s)

= (1^b, g^b^2) * (g^rb, y^rb) * (g^s, y^s)

= (1^b, g^b^2) * (g^rb + s, y^rb + s)

= (g^rb + s, g^b^2 * y^rb + s)

= e(g^b^2, rb+s)


f(b,r,s,t) = (_, g^rb + s, g^b^2 * y^rb + s, _)

f(b1,r1,s1,t1) * f(b2,r2,s2,t2) = f(b1+b2, r1+r2, s1+s2, t1+t2)

(_, g^r1b1 + s1, g^b1^2 * y^r1b1 + s1, _) * (_, g^r2b2, g^b2^2 * y^r2b2 + s2, _) = (_, g^(r1 + r2)(b1 + 2), g^(b1 + b2)^2 * y^(r1+r2)(b1+b2) + (s1 + s2), _)

(_, g^r1b1+r2b2, g^b1^2 + b2^2 * y^r1b1 + s1 + r2b2 + 2) = (_, g^(r1 + r2)(b1 + 2), g^(b1 + b2)^2 * y^(r1+r2)(b1+b2) + (s1 + s2), _)

*/
