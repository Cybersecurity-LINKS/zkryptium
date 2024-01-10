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


use bls12_381_plus::{Scalar, G2Projective, G2Affine};
use elliptic_curve::{group::Curve, hash2curve::ExpandMsg};
use serde::{Serialize, Deserialize};
use crate::{keys::{traits::{PublicKey, PrivateKey}, pair::KeyPair}, schemes::algorithms::BBSplus, errors::Error, utils::util::bbsplus_utils::{i2osp, hash_to_scalar_new}};
use super::ciphersuites::BbsCiphersuite;


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusPublicKey(pub G2Projective);

impl BBSplusPublicKey{

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

    pub fn from_coordinates(x: &[u8; Self::COORDINATE_LEN], y: &[u8; Self::COORDINATE_LEN]) -> Self {
        let mut uncompressed = [0u8; G2Affine::UNCOMPRESSED_BYTES];
        uncompressed[..Self::COORDINATE_LEN].copy_from_slice(x);
        uncompressed[Self::COORDINATE_LEN..].copy_from_slice(y);
        Self::from_bytes_uncompressed(&uncompressed)
    }

    fn to_bytes_uncompressed(&self) -> [u8; G2Affine::UNCOMPRESSED_BYTES] {
        self.0.to_affine().to_uncompressed()
    }

    fn from_bytes_uncompressed(bytes: &[u8; G2Affine::UNCOMPRESSED_BYTES]) -> Self {
        let g2 = G2Projective::from(G2Affine::from_uncompressed(&bytes).unwrap());
        Self(g2)
    }

    pub fn to_bytes(&self) -> [u8; G2Affine::COMPRESSED_BYTES] {
        self.0.to_affine().to_compressed()
    }

    pub fn encode(&self) -> String {
        let pk_bytes = self.to_bytes();
        hex::encode(pk_bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self{
        let bytes: [u8; G2Affine::COMPRESSED_BYTES] = bytes.try_into().expect("Invalid number of bytes to be coverted into a BBSplus public key! (max 96 bytes)");
        let g2 = G2Projective::from(G2Affine::from_compressed(&bytes).unwrap());
        Self(g2)
    }
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusSecretKey(pub Scalar);

impl BBSplusSecretKey{
    //in BE order
    pub fn to_bytes(&self) -> [u8; Scalar::BYTES] {
        let bytes = self.0.to_be_bytes();
        bytes
    }

    pub fn to_bytes_le(&self) -> [u8; Scalar::BYTES] {
        let bytes = self.0.to_le_bytes();
        bytes
    }

    pub fn from_bytes_le(bytes: &[u8]) -> Self {
        let bytes: [u8; Scalar::BYTES] = bytes.try_into().expect("Invalid number of bytes to be coverted into a BBSplus private key! (max 32 bytes)");
        let s = Scalar::from_le_bytes(&bytes).unwrap();

        Self(s)
    }

    pub fn encode(&self) -> String {
        let sk_bytes = self.to_bytes();
        hex::encode(sk_bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let bytes: [u8; Scalar::BYTES] = bytes.try_into().expect("Invalid number of bytes to be coverted into a BBSplus private key! (max 32 bytes)");
        let s = Scalar::from_be_bytes(&bytes).unwrap();

        Self(s)
    }
}



impl PublicKey for BBSplusPublicKey{
    type Output = [u8; 96];
    // type Params = G2Projective;
    fn to_bytes(&self) -> Self::Output {
        self.to_bytes()
    }

    fn encode(&self) -> String {
        let pk_bytes = self.to_bytes();
        hex::encode(pk_bytes)
    }

    // fn get_params(&self) -> Self::Params {
    //     self.0
    // }
}



impl PrivateKey for BBSplusSecretKey{
    type Output = [u8; 32];
    //in BE order
    fn to_bytes(&self) -> Self::Output{
        self.to_bytes()
    }

    fn encode(&self) -> String {
        let sk_bytes = self.to_bytes();
        hex::encode(sk_bytes)
    }
}



impl <CS: BbsCiphersuite> KeyPair<BBSplus<CS>>{ 
    
    pub fn generate(key_material: &[u8], key_info: Option<&[u8]>, key_dst: Option<&[u8]>) -> Result<Self, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {

        let sk = key_gen::<CS>(key_material, key_info, key_dst)?;

        let pk = sk_to_pk(sk);

        Ok(Self{public: BBSplusPublicKey(pk), private: BBSplusSecretKey(sk)})
    }

}


/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-secret-key -> SK = KeyGen(key_material, key_info, key_dst)
/// 
/// # Description
/// This operation generates a secret key (SK) deterministically from a secret octet string (key_material)
/// 
/// # Inputs:
/// * `key_material` (REQUIRED), a secret octet string. See requirements
/// above.
/// * `key_info` (OPTIONAL), an octet string. Defaults to an empty string if
/// not supplied.
/// * `key_dst` (OPTIONAL), an octet string representing the domain separation
/// tag. Defaults to the octet string
/// ciphersuite_id || "KEYGEN_DST_" if not supplied.
///  
pub(crate) fn key_gen<CS>(key_material: &[u8], key_info: Option<&[u8]>, key_dst: Option<&[u8]>) -> Result<Scalar, Error>
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
        return Err(Error::KeyGenError("length(key_info) > 65535".to_owned()))
    }

    let key_dst_default = CS::keygen_dst();
    let key_dst = key_dst.unwrap_or(&key_dst_default);


    // derive_input = key_material || I2OSP(length(key_info), 2) || key_info
    let derive_input = [key_material, &i2osp(key_info.len(), 2), key_info].concat();

    // SK = hash_to_scalar(derive_input, key_dst)
    let sk = hash_to_scalar_new::<CS>(&derive_input, key_dst)?;
    Ok(sk)
}


/// https://identity.foundation/bbs-signature/draft-irtf-cfrg-bbs-signatures.html#name-public-key -> PK = SkToPk(SK)
/// 
/// # Description
/// This operation takes a secret key (SK) and outputs a corresponding public key (PK).
/// 
/// # Inputs:
/// * `sk` (REQUIRED), a secret integer such that 0 < SK < r.
///  
pub(crate) fn sk_to_pk(sk: Scalar) -> G2Projective {
    // W = SK * BP2
    let pk = G2Affine::generator() * sk;
    pk
}