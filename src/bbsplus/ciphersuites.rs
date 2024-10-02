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

use crate::schemes::algorithms::Ciphersuite;
use elliptic_curve::hash2curve::ExpandMsg;
#[cfg(feature = "bbsplus")]
use elliptic_curve::hash2curve::{ExpandMsgXmd, ExpandMsgXof};
#[cfg(feature = "bbsplus")]
use serde::{Deserialize, Serialize};

pub trait BbsCiphersuite: Eq + 'static + Ciphersuite {
    const ID: &'static [u8];
    const API_ID: &'static [u8]; // ciphersuite_id || "H2G_HM2S_"
    const API_ID_BLIND: &'static [u8];
    const COMMIT_DST: &'static [u8];
    const BLIND_PROOF_DST: &'static [u8];
    const KEYGEN_DST: &'static [u8] = b"KEYGEN_DST_";
    const GENERATOR_SEED: &'static [u8] = b"MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_DST: &'static [u8] = b"SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static [u8] = b"SIG_GENERATOR_DST_";
    const MAP_MSG_SCALAR: &'static [u8] = b"MAP_MSG_TO_SCALAR_AS_HASH_";
    const H2S: &'static [u8] = b"H2S_";
    const MOCKED_SCALAR_DST: &'static [u8];
    const SEED_MOCKED_SCALAR: &'static [u8] = b"3.141592653589793238462643383279";

    const P1: &'static str;
    const GENERATOR_SIG_DST: &'static [u8];
    type Expander: for<'a> ExpandMsg<'a>;
    const EXPAND_LEN: usize = 48;
    const OCTECT_SCALAR_LEN: usize = 32;
    const IKM_LEN: usize = 32;
}

#[cfg(feature = "bbsplus")]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Bls12381Shake256 {}
#[cfg(feature = "bbsplus")]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Bls12381Sha256 {}

#[cfg(feature = "bbsplus")]
impl BbsCiphersuite for Bls12381Shake256 {
    const ID: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";
    const API_ID: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_";
    const MOCKED_SCALAR_DST: &'static [u8] =
        b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_";
    const API_ID_BLIND: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_BLIND_H2G_HM2S_";
    const COMMIT_DST: &'static [u8] =
        b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_";
    const BLIND_PROOF_DST: &'static [u8] =
        b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_";
    const GENERATOR_SIG_DST: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_DET_DST_";
    type Expander = ExpandMsgXof<sha3::Shake256>;

    const P1: &'static str = "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755";
}

#[cfg(feature = "bbsplus")]
impl BbsCiphersuite for Bls12381Sha256 {
    const ID: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const API_ID: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
    const MOCKED_SCALAR_DST: &'static [u8] =
        b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_";
    const API_ID_BLIND: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BLIND_H2G_HM2S_";
    const COMMIT_DST: &'static [u8] =
        b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_";
    const BLIND_PROOF_DST: &'static [u8] =
        b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_";
    const GENERATOR_SIG_DST: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_DET_DST_";
    type Expander = ExpandMsgXmd<sha2::Sha256>;

    const P1: &'static str = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9" ;
}
