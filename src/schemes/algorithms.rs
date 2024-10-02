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

use crate::keys::traits::{PrivateKey, PublicKey};
use digest::HashMarker;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[cfg(feature = "bbsplus")]
use crate::bbsplus::ciphersuites::{Bls12381Sha256, Bls12381Shake256};
#[cfg(feature = "min_bbs")]
use crate::bbsplus::{
    ciphersuites::BbsCiphersuite,
    keys::{BBSplusPublicKey, BBSplusSecretKey},
};

#[cfg(feature = "cl03")]
use crate::cl03::{
    ciphersuites::{CL1024Sha256, CLCiphersuite},
    keys::{CL03PublicKey, CL03SecretKey},
};

#[cfg(feature = "bbsplus")]
pub type BbsBls12381Shake256 = BBSplus<Bls12381Shake256>;
#[cfg(feature = "bbsplus")]
pub type BbsBls12381Sha256 = BBSplus<Bls12381Sha256>;

#[cfg(feature = "cl03")]
pub type CL03_CL1024_SHA256 = CL03<CL1024Sha256>;

#[cfg(feature = "min_bbs")]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplus<CS: BbsCiphersuite>(core::marker::PhantomData<CS>);

#[cfg(feature = "cl03")]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03<CS: CLCiphersuite>(core::marker::PhantomData<CS>);

pub trait Ciphersuite: 'static + Eq {
    type HashAlg: HashMarker;
}

#[cfg(feature = "bbsplus")]
impl Ciphersuite for Bls12381Sha256 {
    type HashAlg = sha2::Sha256;
}
#[cfg(feature = "bbsplus")]
impl Ciphersuite for Bls12381Shake256 {
    type HashAlg = sha3::Shake256;
}

pub trait Scheme: Eq + 'static + Sized + Serialize + DeserializeOwned {
    type Ciphersuite: Ciphersuite;
    type PrivKey: PrivateKey;
    type PubKey: PublicKey;
}

#[cfg(feature = "min_bbs")]
impl<CS: BbsCiphersuite> Scheme for BBSplus<CS> {
    type Ciphersuite = CS;
    type PrivKey = BBSplusSecretKey;
    type PubKey = BBSplusPublicKey;
}

#[cfg(feature = "cl03")]
impl<CS: CLCiphersuite> Scheme for CL03<CS> {
    type Ciphersuite = CS;
    type PrivKey = CL03SecretKey;
    type PubKey = CL03PublicKey;
}
