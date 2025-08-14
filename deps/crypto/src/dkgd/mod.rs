use std::array;

use crate::context::Context;
use crate::cryptosystem::elgamal::PublicKey;
use crate::cryptosystem::elgamal::{Ciphertext, KeyPair};
use crate::traits::element::{GroupElement, Narrow};
use crate::traits::scalar::GroupScalar;
use crate::zkp::dlogeq::DlogEqProof;
use vser_derive::VSerializable;

type VerifiableShare<C, const T: usize> = (<C as Context>::Scalar, [<C as Context>::Element; T]);

pub struct DecryptionFactor<C: Context, const W: usize> {
    pub(crate) value: [C::Element; W],
    pub(crate) proof: DlogEqProof<C, W>,
    pub(crate) source: ParticipantPosition,
}
impl<C: Context, const W: usize> DecryptionFactor<C, W> {
    fn new(value: [C::Element; W], proof: DlogEqProof<C, W>, source: ParticipantPosition) -> Self {
        Self {
            value,
            proof,
            source,
        }
    }
}


#[derive(Debug, VSerializable)]
pub struct DkgPublicKey<C: Context, const T: usize>(PublicKey<C>);
impl<C: Context, const T: usize> DkgPublicKey<C, T> {
    pub fn from_keypair(keypair: &KeyPair<C>) -> Self {
        Self(PublicKey {
            y: keypair.pkey.clone(),
        })
    }
    pub fn encrypt<const W: usize>(&self, message: &[C::Element; W]) -> DkgCiphertext<C, W, T> {
        DkgCiphertext::<C, W, T>(self.0.encrypt(message))
    }

    pub fn encrypt_with_r<const W: usize>(
        &self,
        message: &[C::Element; W],
        r: &[C::Scalar; W],
    ) -> DkgCiphertext<C, W, T> {
        DkgCiphertext::<C, W, T>(self.0.encrypt_with_r(message, r))
    }
}

#[derive(Debug, VSerializable)]
pub struct DkgCiphertext<C: Context, const W: usize, const T: usize>(Ciphertext<C, W>);
impl<C: Context, const W: usize, const T: usize> DkgCiphertext<C, W, T> {
    pub fn u(&self) -> &[C::Element; W] {
        self.0.u()
    }
    pub fn v(&self) -> &[C::Element; W] {
        self.0.v()
    }
}

// A polynomial with T coefficients, of degree T - 1
#[derive(Clone)]
pub(crate) struct Polynomial<C: Context, const T: usize>(pub(crate) [C::Scalar; T]);

impl<C: Context, const T: usize> Polynomial<C, T> {
    fn generate() -> Self {
        let coefficients: [C::Scalar; T] = array::from_fn(|_| C::random_scalar());

        Self(coefficients)
    }

    pub(crate) fn eval(&self, x: &C::Scalar) -> C::Scalar {
        let mut sum: C::Scalar = self.0[0].clone();
        let mut power = C::Scalar::one();

        for v in self.0.iter().skip(1) {
            power = power.mul(x);
            sum = sum.add(&v.mul(&power));
        }

        sum
    }
}

// Dealer for threshold = T
#[derive(Clone)]
pub struct Dealer<C: Context, const T: usize, const P: usize> {
    pub(crate) polynomial: Polynomial<C, T>,
}
impl<C: Context, const T: usize, const P: usize> Dealer<C, T, P> {
    pub(crate) fn generate() -> Self {
        let polynomial = Polynomial::<C, T>::generate();
        Self { polynomial }
    }

    pub(crate) fn get_shares(&self) -> [C::Scalar; P] {
        array::from_fn(|p| {
            let recipient: u32 = (p + 1) as u32;
            let recipient: C::Scalar = recipient.into();
            self.polynomial.eval(&recipient)
        })
    }

    pub(crate) fn get_checking_values(&self) -> [C::Element; T] {
        let g = C::generator();
        self.polynomial.0.clone().map(|v| g.exp(&v))
    }
}

// A participant who receives shares for threshold = T
pub struct Recipient<C: Context, const T: usize, const P: usize> {
    // 1-based
    position: ParticipantPosition,
    shares: [VerifiableShare<C, T>; P],
    joint_pk: DkgPublicKey<C, T>,
    verification_key: C::Element,
    sk: C::Scalar,
}
impl<C: Context, const T: usize, const P: usize> Recipient<C, T, P> {
    fn new(position: ParticipantPosition, shares: [VerifiableShare<C, T>; P]) -> Self {
        assert!(position.0 <= P as u32);
        let (joint_pk, verification_key, sk) = Self::verify_shares(&position, &shares).unwrap();
        let joint_pk = DkgPublicKey(PublicKey { y: joint_pk });
        Self {
            position,
            shares,
            joint_pk,
            verification_key,
            sk,
        }
    }

    fn verify_shares(
        position: &ParticipantPosition,
        shares: &[VerifiableShare<C, T>; P],
    ) -> Option<(C::Element, C::Element, C::Scalar)> {
        let mut verification_key = C::Element::one();
        let mut joint_pk = C::Element::one();
        let mut sk = C::Scalar::zero();

        for verifiable_share in shares {
            let result = Self::verify_share(verifiable_share, position);

            if let Some((pk_factor, vk_factor, sk_summand)) = result {
                joint_pk = joint_pk.mul(&pk_factor);
                verification_key = verification_key.mul(&vk_factor);
                sk = sk.add(&sk_summand);
            } else {
                return None;
            }
        }

        Some((joint_pk, verification_key, sk))
    }

    fn verify_share(
        verifiable_share: &VerifiableShare<C, T>,
        position: &ParticipantPosition,
    ) -> Option<(C::Element, C::Element, C::Scalar)> {
        let g = C::generator();
        let share = &verifiable_share.0;
        let checking_values = &verifiable_share.1;
        let lhs = g.exp(share);
        let exponents: [C::Scalar; T] = array::from_fn(|i| {
            let exp = position.0.pow(i as u32);
            exp.into()
        });
        let big_a_n_j = checking_values.exp(&exponents);
        let rhs = big_a_n_j
            .iter()
            .fold(C::Element::one(), |acc, next| acc.mul(next));

        if lhs != rhs {
            return None;
        }

        // pk_factor, vk_factor, sk_summand
        Some((checking_values[0].clone(), rhs, share.clone()))
    }

    fn decryption_factor<const W: usize>(
        &self,
        ciphertext: &DkgCiphertext<C, W, T>,
        proof_context: &[u8],
    ) -> DecryptionFactor<C, W> {
        let dfactor = ciphertext.u().narrow_exp(&self.sk);

        let g = C::generator();
        let proof = DlogEqProof::<C, W>::prove(
            &self.sk,
            &g,
            &self.verification_key,
            ciphertext.u(),
            &dfactor,
            proof_context,
        );

        DecryptionFactor::new(dfactor, proof, self.position.clone())
    }
}

fn reconstruct<C: Context, const T: usize, const W: usize>(
    ciphertext: &DkgCiphertext<C, W, T>,
    dfactors: &[DecryptionFactor<C, W>; T],
    verification_keys: &[C::Element; T],
    context: &[u8],
) -> [C::Element; W] {
    // get the participants
    let present: [ParticipantPosition; T] = array::from_fn(|i| dfactors[i].source.clone());

    let divisor: [[C::Element; W]; T] = array::from_fn(|i| {
        let g = C::generator();
        let proof_ok = dfactors[i].proof.verify(
            &g,
            &verification_keys[i],
            ciphertext.u(),
            &dfactors[i].value,
            context,
        );
        assert!(proof_ok);

        let lagrange = lagrange::<C, T>(&dfactors[i].source, &present);
        dfactors[i].value.narrow_exp(&lagrange)
    });

    let divisor = divisor
        .iter()
        .fold(<[C::Element; W]>::one(), |acc, next| acc.mul(next));

    ciphertext.v().mul(&divisor.inv())
}

// Computes the Lagrange coefficient for the given participant.
fn lagrange<C: Context, const T: usize>(
    trustee: &ParticipantPosition,
    present: &[ParticipantPosition; T],
) -> C::Scalar {
    let mut numerator = C::Scalar::one();
    let mut denominator = C::Scalar::one();
    let trustee_exp: C::Scalar = trustee.0.into();

    for p in present {
        if p.0 == trustee.0 {
            continue;
        }

        let present_exp: C::Scalar = p.0.into();
        let diff_exp = present_exp.sub(&trustee_exp);

        numerator = numerator.mul(&present_exp);
        denominator = denominator.mul(&diff_exp);
    }

    numerator.mul(&denominator.inv().unwrap())
}

#[derive(Clone, Debug)]
pub(crate) struct ParticipantPosition(u32);
impl ParticipantPosition {
    fn new(position: u32) -> Self {
        assert!(position > 0);

        ParticipantPosition(position)
    }
}

#[cfg(test)]
#[crate::warning("Need more threshold parameter combinations")]
mod tests {

    use super::*;
    use crate::context::Context;
    use crate::context::RistrettoCtx as RCtx;
    use crate::context::RistrettoCtx as PCtx;
    use rand::seq::SliceRandom;

    #[test]
    fn test_ristretto() {
        test_::<RCtx, 2, 2, 2>();
        test_::<RCtx, 2, 3, 2>();
        test_::<RCtx, 3, 4, 2>();
    }

    #[test]
    fn test_p256() {
        test_::<PCtx, 2, 2, 2>();
        test_::<PCtx, 2, 3, 2>();
        test_::<PCtx, 3, 4, 2>();
    }

    #[test]
    fn test_non_t_ristretto() {
        test_non_t::<RCtx, 2, 2, 2>();
        test_non_t::<RCtx, 2, 3, 2>();
        test_non_t::<RCtx, 3, 3, 2>();
        test_non_t::<RCtx, 3, 4, 2>();
    }

    #[test]
    fn test_non_t_p256() {
        test_non_t::<PCtx, 2, 2, 2>();
        test_non_t::<PCtx, 2, 3, 2>();
        test_non_t::<PCtx, 3, 3, 2>();
        test_non_t::<PCtx, 3, 4, 2>();
    }

    fn test_<C: Context, const T: usize, const P: usize, const W: usize>() {
        assert!(T <= P);

        let dealers: [Dealer<C, T, P>; P] = array::from_fn(|_| Dealer::generate());

        let mut recipients: [Recipient<C, T, P>; P] = array::from_fn(|i| {
            let verifiable_shares: [VerifiableShare<C, T>; P] = dealers.clone().map(|d| {
                let shares = d.get_shares()[i].clone();
                (shares, d.get_checking_values())
            });
            let position = (i + 1) as u32;

            Recipient::new(ParticipantPosition::new(position), verifiable_shares)
        });

        let mut rng = C::get_rng();
        recipients.shuffle(&mut rng);

        let pk: &DkgPublicKey<C, T> = &recipients[0].joint_pk;

        let message: [C::Element; W] = array::from_fn(|_| C::random_element());
        let encrypted = pk.encrypt(&message);

        let verification_keys: [C::Element; T] =
            array::from_fn(|i| recipients[i].verification_key.clone());

        let dfactors: [DecryptionFactor<C, W>; P] =
            recipients.map(|r| r.decryption_factor(&encrypted, &vec![]));

        let threshold: &[DecryptionFactor<C, W>; T] =
            dfactors[0..T].try_into().expect("impossible");
        let decrypted = reconstruct(&encrypted, &threshold, &verification_keys, &vec![]);
        assert!(message == decrypted);

        let decrypted = untyped_reconstruct(&encrypted.0, &threshold[1..]);
        assert!(message != decrypted);
    }

    fn test_non_t<C: Context, const T: usize, const P: usize, const W: usize>() {
        assert!(T <= P);

        let dealers: [Dealer<C, T, P>; P] = array::from_fn(|_| Dealer::generate());

        let recipients: [Recipient<C, T, P>; P] = array::from_fn(|i| {
            let verifiable_shares: [VerifiableShare<C, T>; P] = dealers.clone().map(|d| {
                let shares = d.get_shares()[i].clone();
                (shares, d.get_checking_values())
            });
            let position = (i + 1) as u32;

            Recipient::new(ParticipantPosition::new(position), verifiable_shares)
        });

        let pk: &DkgPublicKey<C, T> = &recipients[0].joint_pk;

        let message: [C::Element; W] = array::from_fn(|_| C::random_element());
        let encrypted = pk.encrypt(&message);

        let mut dfactors: [DecryptionFactor<C, W>; P] =
            recipients.map(|r| r.decryption_factor(&encrypted, &vec![]));
        let mut rng = C::get_rng();
        dfactors.shuffle(&mut rng);

        let decrypted = untyped_reconstruct(&encrypted.0, &dfactors);
        assert!(message == decrypted);
    }

    fn untyped_reconstruct<C: Context, const W: usize>(
        ciphertext: &Ciphertext<C, W>,
        dfactors: &[DecryptionFactor<C, W>],
    ) -> [C::Element; W] {
        // first get the participating trustees
        let present: Vec<ParticipantPosition> =
            dfactors.iter().map(|df| df.source.clone()).collect();

        let divisor: Vec<[C::Element; W]> = dfactors
            .iter()
            .map(|df| {
                let lagrange = untyped_lagrange::<C>(&df.source, &present);
                df.value.narrow_exp(&lagrange)
            })
            .collect();

        let divisor = divisor
            .iter()
            .fold(<[C::Element; W]>::one(), |acc, next| acc.mul(next));

        ciphertext.v().mul(&divisor.inv())
    }

    fn untyped_lagrange<C: Context>(
        trustee: &ParticipantPosition,
        present: &[ParticipantPosition],
    ) -> C::Scalar {
        let mut numerator = C::Scalar::one();
        let mut denominator = C::Scalar::one();
        let trustee_exp: C::Scalar = trustee.0.into();

        for p in present {
            if p.0 == trustee.0 {
                continue;
            }

            let present_exp: C::Scalar = p.0.into();
            let diff_exp = present_exp.sub(&trustee_exp);

            numerator = numerator.mul(&present_exp);
            denominator = denominator.mul(&diff_exp);
        }

        numerator.mul(&denominator.inv().unwrap())
    }
}
