// Copyright 2023 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::{borrow::ToOwned, string::String};
use super::ciphersuites::BbsCiphersuite;
use crate::{
    errors::Error,
    keys::{
        pair::KeyPair,
        traits::{PrivateKey, PublicKey},
    },
    schemes::algorithms::BBSplus,
    utils::util::bbsplus_utils::{
        generate_random_secret, hash_to_scalar, i2osp, parse_g2_projective_compressed,
        parse_g2_projective_uncompressed,
    },
};
use bls12_381_plus::{G2Affine, G2Projective, Scalar};
use elliptic_curve::{group::Curve, hash2curve::ExpandMsg};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusPublicKey(pub G2Projective);

impl BBSplusPublicKey {
    pub const COORDINATE_LEN: usize = G2Affine::UNCOMPRESSED_BYTES / 2;

    /// Get (x, y) coordinates
    pub fn to_coordinates(&self) -> ([u8; Self::COORDINATE_LEN], [u8; Self::COORDINATE_LEN]) {
        let uncompressed: [u8; G2Affine::UNCOMPRESSED_BYTES] = self.to_bytes_uncompressed();
        let mut x = [0u8; G2Affine::UNCOMPRESSED_BYTES / 2];
        let mut y = [0u8; G2Affine::UNCOMPRESSED_BYTES / 2];
        let mid_index = G2Affine::UNCOMPRESSED_BYTES / 2;
        let (first, second) = uncompressed.split_at(mid_index).try_into().unwrap();
        x.copy_from_slice(first);
        y.copy_from_slice(second);
        (x, y)
    }

    pub fn from_coordinates(
        x: &[u8; Self::COORDINATE_LEN],
        y: &[u8; Self::COORDINATE_LEN],
    ) -> Result<Self, Error> {
        let mut uncompressed = [0u8; G2Affine::UNCOMPRESSED_BYTES];
        uncompressed[..Self::COORDINATE_LEN].copy_from_slice(x);
        uncompressed[Self::COORDINATE_LEN..].copy_from_slice(y);
        Self::from_bytes_uncompressed(&uncompressed)
    }

    fn to_bytes_uncompressed(&self) -> [u8; G2Affine::UNCOMPRESSED_BYTES] {
        self.0.to_affine().to_uncompressed()
    }

    fn from_bytes_uncompressed(bytes: &[u8; G2Affine::UNCOMPRESSED_BYTES]) -> Result<Self, Error> {
        let g2 =
            parse_g2_projective_uncompressed(bytes).map_err(|_| Error::KeyDeserializationError)?;
        Ok(Self(g2))
    }

    pub fn to_bytes(&self) -> [u8; G2Affine::COMPRESSED_BYTES] {
        self.0.to_affine().to_compressed()
    }

    pub fn encode(&self) -> String {
        let pk_bytes = self.to_bytes();
        hex::encode(pk_bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let g2 = parse_g2_projective_compressed(&bytes[0..G2Affine::COMPRESSED_BYTES])
            .map_err(|_| Error::KeyDeserializationError)?;
        Ok(Self(g2))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusSecretKey(pub Scalar);

impl BBSplusSecretKey {
    /// In Big Endian order
    pub fn to_bytes(&self) -> [u8; Scalar::BYTES] {
        let bytes = self.0.to_be_bytes();
        bytes
    }

    pub fn encode(&self) -> String {
        let sk_bytes = self.to_bytes();
        hex::encode(sk_bytes)
    }

    /// Returns the corresponding [`BBSplusPublicKey`].
    pub fn public_key(&self) -> BBSplusPublicKey {
        BBSplusPublicKey(sk_to_pk(self.0))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: [u8; Scalar::BYTES] = bytes
            .try_into()
            .map_err(|_| Error::KeyDeserializationError)?;
        let s = Scalar::from_be_bytes(&bytes);
        if s.is_none().into() {
            return Err(Error::KeyDeserializationError);
        }

        Ok(Self(s.unwrap()))
    }
}

impl PublicKey for BBSplusPublicKey {
    type Output = [u8; 96];

    fn to_bytes(&self) -> Self::Output {
        self.to_bytes()
    }

    fn encode(&self) -> String {
        let pk_bytes = self.to_bytes();
        hex::encode(pk_bytes)
    }
}

impl PrivateKey for BBSplusSecretKey {
    type Output = [u8; 32];
    /// In Big Endian order
    fn to_bytes(&self) -> Self::Output {
        self.to_bytes()
    }

    fn encode(&self) -> String {
        let sk_bytes = self.to_bytes();
        hex::encode(sk_bytes)
    }
}

impl<CS: BbsCiphersuite> KeyPair<BBSplus<CS>> {
    /// # Description
    /// This operation generates a keypair (SK, PK) deterministically from a secret octet string (key_material)
    ///
    /// # Inputs:
    /// * `key_material` (REQUIRED), a secret octet string.
    /// * `key_info` (OPTIONAL), an octet string. Defaults to an empty string if not supplied.
    /// * `key_dst` (OPTIONAL), an octet string representing the domain separation tag. Defaults to the octet string [`BbsCiphersuite::API_ID`] || "KEYGEN_DST_"
    /// # Output:
    /// * a keypair [`KeyPair`]
    ///  
    pub fn generate(
        key_material: &[u8],
        key_info: Option<&[u8]>,
        key_dst: Option<&[u8]>,
    ) -> Result<Self, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let sk = key_gen::<CS>(key_material, key_info, key_dst)?;

        let pk = sk_to_pk(sk);

        Ok(Self {
            public: BBSplusPublicKey(pk),
            private: BBSplusSecretKey(sk),
        })
    }

    /// # Description
    /// This operation generates a random keypair (SK, PK)
    ///
    /// # Output:
    /// * a keypair [`KeyPair`]
    pub fn random() -> Result<Self, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let key_material = generate_random_secret(64);
        let sk = key_gen::<CS>(&key_material, None, None)?;

        let pk = sk_to_pk(sk);

        Ok(Self {
            public: BBSplusPublicKey(pk),
            private: BBSplusSecretKey(sk),
        })
    }
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-secret-key -> SK = KeyGen(key_material, key_info, key_dst)
///
/// # Description
/// This operation generates a secret key (SK) deterministically from a secret octet string (key_material)
///
/// # Inputs:
/// * `key_material` (REQUIRED), a secret octet string. MUST be at least 32 Bytes.
/// * `key_info` (OPTIONAL), an octet string. Defaults to an empty string if
/// not supplied.
/// * `key_dst` (OPTIONAL), an octet string representing the domain separation
/// tag. Defaults to the octet string
/// ciphersuite_id || "KEYGEN_DST_" if not supplied.
/// # Output:
/// * SK, a [`Scalar`]
///  
fn key_gen<CS>(
    key_material: &[u8],
    key_info: Option<&[u8]>,
    key_dst: Option<&[u8]>,
) -> Result<Scalar, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    // if length(key_material) < 32, return INVALID
    if key_material.len() < CS::IKM_LEN {
        return Err(Error::KeyGenError("length(key_material) < 32".to_owned()));
    }

    let key_info = key_info.unwrap_or(&[]);

    // if length(key_info) > 65535, return INVALID
    if key_info.len() > 65535 {
        return Err(Error::KeyGenError("length(key_info) > 65535".to_owned()));
    }

    let key_dst_default = [CS::API_ID, CS::KEYGEN_DST].concat();
    let key_dst = key_dst.unwrap_or(&key_dst_default);

    // derive_input = key_material || I2OSP(length(key_info), 2) || key_info
    let derive_input = [key_material, &i2osp::<2>(key_info.len()), key_info].concat();

    // SK = hash_to_scalar(derive_input, key_dst)
    let sk = hash_to_scalar::<CS>(&derive_input, key_dst)?;
    Ok(sk)
}

/// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-public-key -> PK = SkToPk(SK)
///
/// # Description
/// This operation takes a secret key (SK) and outputs a corresponding public key (PK).
///
/// # Inputs:
/// * `sk` (REQUIRED), a secret integer such that 0 < SK < r.
/// # Output:
/// * PK, a [`G2Projective`]
///
fn sk_to_pk(sk: Scalar) -> G2Projective {
    // W = SK * BP2
    let pk = G2Affine::generator() * sk;
    pk
}

#[cfg(test)]
mod tests {

    use crate::bbsplus::ciphersuites::BbsCiphersuite;
    use crate::schemes::algorithms::Scheme;
    use crate::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
    use crate::{keys::pair::KeyPair, schemes::algorithms::BBSplus};
    use std::fs;

    //KEYPAIR - SHA256

    #[test]
    fn keypair_sha256() {
        key_pair_gen::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/keypair.json");
    }

    //KEYPAIR - SHAKE256

    #[test]
    fn keypair_shake256() {
        key_pair_gen::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/keypair.json");
    }

    fn key_pair_gen<S: Scheme>(filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        eprintln!("Key Pair");
        let data = fs::read_to_string(filename).expect("Unable to read file");
        let data_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        let IKM = data_json["keyMaterial"].as_str().unwrap();
        let KEY_INFO = data_json["keyInfo"].as_str().unwrap();
        let KEY_DST = data_json["keyDst"].as_str().unwrap();
        let SK_expected = data_json["keyPair"]["secretKey"].as_str().unwrap();
        let PK_expected = data_json["keyPair"]["publicKey"].as_str().unwrap();

        let keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
            &hex::decode(IKM).unwrap(),
            Some(&hex::decode(KEY_INFO).unwrap()),
            Some(&hex::decode(KEY_DST).unwrap()),
        )
        .unwrap();

        let sk = keypair.private_key().encode();
        let pk = keypair.public_key().encode();

        let result1 = sk == SK_expected;

        if result1 == false {
            println!("      keyGen:        {}", result1);
            println!("      Expected key:  {}", SK_expected);
            println!("      Generated key: {}", sk);
        }

        let result2 = pk == PK_expected;

        if result2 == false {
            println!("      skToPk:        {}", result2);
            println!("      Expected key:  {}", PK_expected);
            println!("      Generated key: {}", pk);
        }
        let result = result1 && result2;

        assert!(result, "Failed");
    }
}
