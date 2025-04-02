// Copyright 2025 Fondazione LINKS

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
use std::marker::PhantomData;

#[cfg(feature = "bbsplus")]
use crate::bbsplus::{
    ciphersuites::{BbsCiphersuite, Bls12381Sha256, Bls12381Shake256},
    keys::{BBSplusPublicKey, BBSplusSecretKey},
};

#[cfg(feature = "cl03")]
use crate::cl03::{
    ciphersuites::{CL1024Sha256, CL2048Sha256, CL3072Sha256, CLCiphersuite},
    keys::{CL03PublicKey, CL03SecretKey},
};
#[cfg(feature = "bbsplus")]
/// Type alias for BBS+ scheme using BLS12-381 curve and SHAKE256 hash function.
pub type BbsBls12381Shake256 = BBSplus<Bls12381Shake256>;
#[cfg(feature = "bbsplus")]
/// Type alias for BBS+ scheme using BLS12-381 curve and SHA256 hash function.
pub type BbsBls12381Sha256 = BBSplus<Bls12381Sha256>;

/// Type alias for CL03 scheme using SHA256 hash function and 1024 bit key.
#[cfg(feature = "cl03")]
pub type CL03_CL1024_SHA256 = CL03<CL1024Sha256>;
/// Type alias for CL03 scheme using SHA256 hash function and 2048 bit key.
#[cfg(feature = "cl03")]
pub type CL03_CL2048_SHA256 = CL03<CL2048Sha256>;
/// Type alias for CL03 scheme using SHA256 hash function and 3072 bit key.
#[cfg(feature = "cl03")]
pub type CL03_CL3072_SHA256 = CL03<CL3072Sha256>;

#[cfg(feature = "bbsplus")]
/// A struct representing the BBS+ scheme with a specific ciphersuite.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplus<CS: BbsCiphersuite>(PhantomData<CS>);

/// A struct representing the CL03 scheme with a specific ciphersuite.
#[cfg(feature = "cl03")]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03<CS: CLCiphersuite>(PhantomData<CS>);

/// A trait representing a cryptographic ciphersuite.
pub trait Ciphersuite: 'static + Eq {
    /// The hash algorithm used by the ciphersuite.
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

/// A trait representing a cryptographic scheme.
pub trait Scheme: Eq + 'static + Sized + Serialize + DeserializeOwned {
    /// The ciphersuite used by the scheme.
    type Ciphersuite: Ciphersuite;
    /// The private key type used by the scheme.
    type PrivKey: PrivateKey;
    /// The public key type used by the scheme.
    type PubKey: PublicKey;
}

#[cfg(feature = "bbsplus")]
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
