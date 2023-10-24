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
use elliptic_curve::group::Curve;
use ff::Field;
use hkdf::Hkdf;
use rand::{RngCore, Rng};
use serde::{Serialize, Deserialize};
use sha2::Sha256;
use digest::Digest;
use crate::{keys::{traits::{PublicKey, PrivateKey}, pair::KeyPair}, schemes::algorithms::BBSplus};
use super::ciphersuites::BbsCiphersuite;



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusPublicKey(pub G2Projective);

impl BBSplusPublicKey{
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_affine().to_compressed()
    }

    pub fn encode(&self) -> String {
        let pk_bytes = self.to_bytes();
        hex::encode(pk_bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self{
        let bytes: [u8; 96] = bytes.try_into().expect("Invalid number of bytes to be coverted into a BBSplus public key! (max 96 bytes)");
        let g2 = G2Projective::from(G2Affine::from_compressed(&bytes).unwrap());
        Self(g2)
    }
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusSecretKey(pub Scalar);

impl BBSplusSecretKey{
    //in BE order
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_be_bytes();
        // bytes.reverse();
        bytes
    }

    pub fn encode(&self) -> String {
        let sk_bytes = self.to_bytes();
        hex::encode(sk_bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let bytes: [u8; 32] = bytes.try_into().expect("Invalid number of bytes to be coverted into a BBSplus private key! (max 32 bytes)");
        // bytes.reverse();
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
     
    pub fn generate_rng<R: RngCore>(rng: &mut R) -> Self {
        let sk = Scalar::random(rng);
        let pk: G2Projective = (G2Affine::generator() * sk).into();

        Self{public: BBSplusPublicKey(pk), private: BBSplusSecretKey(sk)}
    }
    
    pub fn generate(ikm: Option<&[u8]>, key_info: Option<&[u8]>) -> Self
    {

        let ikm = if let Some(ikm_data) = ikm {
            ikm_data.to_vec()
        } else {
            let mut rng = rand::thread_rng();
            (0..CS::IKM_LEN).map(|_| rng.gen()).collect()
        };

        let ikm = ikm.as_ref();
        

        let key_info = key_info.unwrap_or(&[]);
        let init_salt = "BBS-SIG-KEYGEN-SALT-".as_bytes();
    
        // if ikm.len() < 32 {
        //     return Err(BadParams { 
        //         cause: format!("Invalid ikm length. Needs to be at least 32 bytes long. Got {}", ikm.len())
        //     })
        // }
    
        // L = ceil((3 * ceil(log2(r))) / 16)
        const L: usize = 48;
        const L_BYTES: [u8; 2] = (L as u16).to_be_bytes();
    
        // salt = H(salt)
        let mut hasher = Sha256::new();
        hasher.update(init_salt);
        let salt = hasher.finalize();
    
        // PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
        let prk = Hkdf::<Sha256>::new(
            Some(&salt),
            &[ikm, &[0u8; 1][..]].concat()
        );
    
        // OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
        let mut okm = [0u8; 64];
    
        prk.expand(
            &[&key_info, &L_BYTES[..]].concat(),
            &mut okm[(64-L)..]
        ).expect(
            &format!("The HKDF-expand output cannot be more than {} bytes long", 255 * Sha256::output_size())
        );
    
        okm.reverse(); // okm is in be format
        let sk = Scalar::from_bytes_wide(&okm);
        let pk: G2Projective = G2Affine::generator() * sk;
        // let pk_affine = pk.to_affine();
    
        // // transform secret key from le to be
        // let mut sk_bytes = sk.to_bytes();
        // sk_bytes.reverse();

        // BBSplusKeyPair::new(BBSplusSecretKey(sk), BBSplusPublicKey(pk))

        Self{public: BBSplusPublicKey(pk), private: BBSplusSecretKey(sk)}
    }

}
