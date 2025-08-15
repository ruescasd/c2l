use crate::context::{Context, RistrettoCtx};
use crate::cryptosystem::{elgamal, naoryung};
use crate::dkgd::{DkgCiphertext, DkgPublicKey};
use crate::dkgd::{VerifiableShares, VerifiableShare, DecryptionFactor};
use crate::utils::serialization::{VDeserializable, VSerializable};
use crate::zkp::{
    dlogeq::DlogEqProof, pleq::PlEqProof, schnorr::SchnorrProof,
    shuffle::{Responses, ShuffleCommitments, ShuffleProof},
};
use serde::{self, de::Error, Deserializer, Serializer};

// elgamal::PublicKey
impl<'de, C: Context> serde::Deserialize<'de> for elgamal::PublicKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context> serde::Serialize for elgamal::PublicKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// elgamal::KeyPair
impl<'de, C: Context> serde::Deserialize<'de> for elgamal::KeyPair<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context> serde::Serialize for elgamal::KeyPair<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// elgamal::Ciphertext
impl<'de, C: Context, const W: usize> serde::Deserialize<'de> for elgamal::Ciphertext<C, W> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const W: usize> serde::Serialize for elgamal::Ciphertext<C, W> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// naoryung::KeyPair
impl<'de, C: Context> serde::Deserialize<'de> for naoryung::KeyPair<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context> serde::Serialize for naoryung::KeyPair<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// naoryung::Ciphertext
impl<'de, C: Context, const N: usize> serde::Deserialize<'de> for naoryung::Ciphertext<C, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const N: usize> serde::Serialize for naoryung::Ciphertext<C, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// DlogEqProof
impl<'de, C: Context, const N: usize> serde::Deserialize<'de> for DlogEqProof<C, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const N: usize> serde::Serialize for DlogEqProof<C, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// PlEqProof
impl<'de, C: Context, const N: usize> serde::Deserialize<'de> for PlEqProof<C, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const N: usize> serde::Serialize for PlEqProof<C, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// SchnorrProof
impl<'de, C: Context> serde::Deserialize<'de> for SchnorrProof<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context> serde::Serialize for SchnorrProof<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// ShuffleProof
impl<'de, C: Context, const W: usize> serde::Deserialize<'de> for ShuffleProof<C, W> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const W: usize> serde::Serialize for ShuffleProof<C, W> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// Responses
impl<'de, C: Context, const W: usize> serde::Deserialize<'de> for Responses<C, W> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const W: usize> serde::Serialize for Responses<C, W> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// ShuffleCommitments
impl<'de, C: Context, const W: usize> serde::Deserialize<'de> for ShuffleCommitments<C, W> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const W: usize> serde::Serialize for ShuffleCommitments<C, W> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// DkgPublicKey
impl<'de, C: Context, const T: usize> serde::Deserialize<'de> for DkgPublicKey<C, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const T: usize> serde::Serialize for DkgPublicKey<C, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// DkgCiphertext
impl<'de, C: Context, const W: usize, const T: usize> serde::Deserialize<'de> for DkgCiphertext<C, W, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const W: usize, const T: usize> serde::Serialize for DkgCiphertext<C, W, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// VerifiableShare
impl<'de, C: Context, const T: usize> serde::Deserialize<'de> for VerifiableShare<C, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const T: usize> serde::Serialize for VerifiableShare<C, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// DecryptionFactor
impl<'de, C: Context, const T: usize> serde::Deserialize<'de> for DecryptionFactor<C, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const T: usize> serde::Serialize for DecryptionFactor<C, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// naoryung::PublicKey
impl<'de, C: Context, const T: usize, const P: usize> serde::Deserialize<'de> for VerifiableShares<C, T, P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context, const T: usize, const P: usize> serde::Serialize for VerifiableShares<C, T, P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// naoryung::PublicKey
impl<'de, C: Context> serde::Deserialize<'de> for naoryung::PublicKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        Self::deser(&bytes).map_err(D::Error::custom)
    }
}

impl<C: Context> serde::Serialize for naoryung::PublicKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.ser())
    }
}

// RistrettoCtx
impl<'de> serde::Deserialize<'de> for RistrettoCtx {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(RistrettoCtx)
    }
}

impl serde::Serialize for RistrettoCtx {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&vec![])
    }
}

#[cfg(test)]
mod tests {
    
    use crate::context::{Context, P256Ctx, RistrettoCtx as RCtx};
    use crate::cryptosystem::{elgamal, naoryung};
    use crate::dkgd::{DkgCiphertext, DkgPublicKey};
    use crate::traits::group::CryptoGroup;
    use crate::zkp::{dlogeq, pleq, schnorr, shuffle};
    use crate::traits::element::{Narrow, GroupElement};

    #[test]
    fn test_serde_elgamal_public_key() {
        let pk = elgamal::KeyPair::generate().pkey;
        let serialized = bincode::serde::encode_to_vec(&pk, bincode::config::standard()).unwrap();
        let (deserialized, _): (elgamal::PublicKey<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(pk, deserialized);
    }
/* 
    #[test]
    fn test_serde_naoryung_public_key() {
        let pk =
            elgamal::PublicKey::<P256Ctx>::from_keypair(&elgamal::KeyPair::generate());
        let serialized = bincode::serde::encode_to_vec(&pk, bincode::config::standard()).unwrap();
        let (deserialized, _): (elgamal::PublicKey<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(pk, deserialized);
    }
*/
    #[test]
    fn test_serde_elgamal_key_pair() {
        let kp = elgamal::KeyPair::<P256Ctx>::generate();
        let serialized = bincode::serde::encode_to_vec(&kp, bincode::config::standard()).unwrap();
        let (deserialized, _): (elgamal::KeyPair<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(kp, deserialized);
    }

    #[test]
    fn test_serde_elgamal_ciphertext() {
        let kp = elgamal::KeyPair::<P256Ctx>::generate();
        let m = [P256Ctx::random_element(), P256Ctx::random_element()];
        let ct = kp.encrypt(&m);

        let serialized = bincode::serde::encode_to_vec(&ct, bincode::config::standard()).unwrap();
        let (deserialized, _): (elgamal::Ciphertext<P256Ctx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(ct, deserialized);
    }

    #[test]
    fn test_serde_naoryung_key_pair() {
        let eg_kp = elgamal::KeyPair::<P256Ctx>::generate();
        let kp = naoryung::KeyPair::new(&eg_kp, P256Ctx::random_element());
        let serialized = bincode::serde::encode_to_vec(&kp, bincode::config::standard()).unwrap();
        let (deserialized, _): (naoryung::KeyPair<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(kp, deserialized);
    }

    #[test]
    fn test_serde_naoryung_ciphertext() {
        let eg_kp = elgamal::KeyPair::<P256Ctx>::generate();
        let kp = naoryung::KeyPair::new(&eg_kp, P256Ctx::random_element());
        let m = [P256Ctx::random_element(), P256Ctx::random_element()];
        let ct = kp.encrypt(&m);

        let serialized = bincode::serde::encode_to_vec(&ct, bincode::config::standard()).unwrap();
        let (deserialized, _): (naoryung::Ciphertext<P256Ctx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(ct, deserialized);
    }

    #[test]
    fn test_serde_dlogeq_proof() {
        let secret_x = P256Ctx::random_scalar();
        let g1 = P256Ctx::random_element();
        let gn = [P256Ctx::random_element(), P256Ctx::random_element()];

        let public_y1 = g1.exp(&secret_x);
        let public_yn = gn.narrow_exp(&secret_x);

        let proof: dlogeq::DlogEqProof<P256Ctx, 2> =
            dlogeq::DlogEqProof::prove(&secret_x, &g1, &public_y1, &gn, &public_yn, &vec![]);
        let serialized = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (deserialized, _): (dlogeq::DlogEqProof<P256Ctx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_serde_pleq_proof() {
        let eg_kp = elgamal::KeyPair::<RCtx>::generate();
        let ny_kp = naoryung::KeyPair::new(&eg_kp, RCtx::random_element());
        let m = [
            RCtx::random_element(),
            RCtx::random_element(),
        ];
        let r = [RCtx::random_scalar(), RCtx::random_scalar()];
        let ct = ny_kp.encrypt_with_r(&m, &r);

        let proof: pleq::PlEqProof<RCtx, 2> =
            pleq::PlEqProof::prove(&ny_kp.pkey.pk_b, &ny_kp.pkey.pk_a, &ct.u_b, &ct.v_b, &ct.u_a, &r);
        let serialized = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (deserialized, _): (pleq::PlEqProof<RCtx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_serde_schnorr_proof() {
        let g = P256Ctx::generator();
        let secret_x = P256Ctx::random_scalar();
        let public_y = g.exp(&secret_x);

        let proof = schnorr::SchnorrProof::<P256Ctx>::prove(&g, &public_y, &secret_x);
        let serialized = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (deserialized, _): (schnorr::SchnorrProof<P256Ctx>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_serde_shuffle_proof() {
        const W: usize = 2;
        let count = 2;
        let keypair: elgamal::KeyPair<P256Ctx> = elgamal::KeyPair::generate();

        let messages: Vec<[<P256Ctx as crate::context::Context>::Element; W]> = (0..count)
            .map(|_| std::array::from_fn(|_| P256Ctx::random_element()))
            .collect();

        let ciphertexts: Vec<elgamal::Ciphertext<P256Ctx, W>> =
            messages.iter().map(|m| keypair.encrypt(m)).collect();

        let generators = <P256Ctx as Context>::G::ind_generators(count, &vec![]);
        let shuffler = shuffle::Shuffler::<P256Ctx, W>::new(generators, keypair.pkey);

        let (_, proof) = shuffler.shuffle(&ciphertexts, &vec![]);
        let serialized = bincode::serde::encode_to_vec(&proof, bincode::config::standard()).unwrap();
        let (deserialized, _): (shuffle::ShuffleProof<P256Ctx, W>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_serde_dkg_public_key() {
        let keypair = elgamal::KeyPair::<P256Ctx>::generate();
        let pk = DkgPublicKey::<P256Ctx, 2>::from_keypair(&keypair);
        let serialized = bincode::serde::encode_to_vec(&pk, bincode::config::standard()).unwrap();
        let (deserialized, _): (DkgPublicKey<P256Ctx, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(pk, deserialized);
    }

    #[test]
    fn test_serde_dkg_ciphertext() {
        let keypair = elgamal::KeyPair::<P256Ctx>::generate();
        let pk = DkgPublicKey::<P256Ctx, 2>::from_keypair(&keypair);
        let m = [P256Ctx::random_element(), P256Ctx::random_element()];
        let ct: DkgCiphertext<P256Ctx, 2, 2> = pk.encrypt(&m);
        let serialized = bincode::serde::encode_to_vec(&ct, bincode::config::standard()).unwrap();
        let (deserialized, _): (DkgCiphertext<P256Ctx, 2, 2>, _) =
            bincode::serde::decode_from_slice(&serialized, bincode::config::standard()).unwrap();
        assert_eq!(ct, deserialized);
    }
}
