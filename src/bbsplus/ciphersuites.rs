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

use serde::{Deserialize, Serialize};
use sha3::Shake256;
use sha2::Sha256;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXof, ExpandMsgXmd};
use crate::schemes::algorithms::Ciphersuite;


pub trait BbsCiphersuite: Eq + 'static + Ciphersuite{
    const ID: &'static [u8];
    const API_ID: &'static [u8]; // ciphersuite_id || "H2G_HM2S_"
    const GENERATOR_SEED: &'static [u8] = b"MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_DST: &'static [u8] = b"SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static [u8] = b"SIG_GENERATOR_DST_";
    const MAP_MSG_SCALAR: &'static [u8] = b"MAP_MSG_TO_SCALAR_AS_HASH_";
    const H2S: &'static [u8] = b"H2S_";
    const MOCKED_SCALAR: &'static [u8] = b"MOCK_RANDOM_SCALARS_DST_";
    const SEED_MOCKED_SCALAR: &'static [u8] = b"332e313431353932363533353839373933323338343632363433333833323739";

    const P1: &'static str;
    const GENERATOR_SIG_DST: &'static [u8];
    type Expander: for<'a> ExpandMsg<'a>;
    const EXPAND_LEN: usize = 48;
    const OCTECT_SCALAR_LEN: usize = 32;
    const IKM_LEN: usize = 32;


    fn keygen_dst() -> Vec<u8> {
        [Self::API_ID, b"KEYGEN_DST_"].concat()
    }

    fn map_msg_to_scalar_as_hash_dst() -> Vec<u8> {
        [Self::API_ID, b"MAP_MSG_TO_SCALAR_AS_HASH_"].concat()
    }

    fn generator_seed() -> Vec<u8> {
        [Self::API_ID, b"MESSAGE_GENERATOR_SEED"].concat()
    }

    fn generator_seed_dst() -> Vec<u8> {
        [Self::API_ID, b"SIG_GENERATOR_SEED_"].concat()
    }

    fn generator_dst() -> Vec<u8> {
        [Self::API_ID, b"SIG_GENERATOR_DST_"].concat()
    }
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Bls12381Shake256{}
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Bls12381Sha256 {}


impl BbsCiphersuite for Bls12381Shake256 {
    const ID: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";
    const API_ID: &'static [u8] =  b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_";
    const GENERATOR_SIG_DST: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_DET_DST_";
    type Expander= ExpandMsgXof<Shake256>;


    const P1: &'static str = "8929dfbc7e6642c4ed9cba0856e493f8b9d7d5fcb0c31ef8fdcd34d50648a56c795e106e9eada6e0bda386b414150755";


}


impl BbsCiphersuite for Bls12381Sha256 {
    const ID: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const API_ID: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_";
    const GENERATOR_SIG_DST: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_DET_DST_";
    type Expander= ExpandMsgXmd<Sha256>;

    const P1: &'static str = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9" ;
}

