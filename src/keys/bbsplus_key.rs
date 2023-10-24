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
use serde::{Serialize, Deserialize};

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