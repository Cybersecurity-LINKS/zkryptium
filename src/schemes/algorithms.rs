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

use digest::HashMarker;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use sha2::Sha256;
use sha3::Shake256;
use std::marker::PhantomData;
use crate::{keys::{traits::{PrivateKey, PublicKey}}, bbsplus::{ciphersuites::{BbsCiphersuite, Bls12381Shake256, Bls12381Sha256}, keys::{BBSplusSecretKey, BBSplusPublicKey}}, cl03::{ciphersuites::{CLCiphersuite, CL1024Sha256}, keys::{CL03SecretKey, CL03PublicKey}}};

pub type BBS_BLS12381_SHAKE256 = BBSplus<Bls12381Shake256>;
pub type BBS_BLS12381_SHA256 = BBSplus<Bls12381Sha256>;
pub type CL03_CL1024_SHA256 = CL03<CL1024Sha256>;



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplus<CS: BbsCiphersuite>(PhantomData<CS>);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03<CS: CLCiphersuite>(PhantomData<CS>);


pub trait Ciphersuite: 'static + Eq{
    type HashAlg: HashMarker;

}

impl Ciphersuite for Bls12381Sha256{
    type HashAlg = Shake256;

}
impl Ciphersuite for Bls12381Shake256{
    type HashAlg = Sha256;

}


pub trait Scheme:
Eq
+ 'static
+ Sized 
+ Serialize 
+ DeserializeOwned {
    type Ciphersuite: Ciphersuite;
    type PrivKey: PrivateKey;
    type PubKey: PublicKey;
}

impl <CS: BbsCiphersuite> Scheme for BBSplus<CS> {
    type Ciphersuite = CS;
    type PrivKey = BBSplusSecretKey;
    type PubKey = BBSplusPublicKey;
}

impl <CS: CLCiphersuite> Scheme for CL03<CS> {
    type Ciphersuite = CS;
    type PrivKey = CL03SecretKey;
    type PubKey = CL03PublicKey;


}