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

use std::collections::VecDeque;

use bls12_381_plus::G1Projective;
use elliptic_curve::group::Curve;
use elliptic_curve::hash2curve::{ExpandMsg, Expander};
use serde::{Serialize, Deserialize};
use serde::ser::{Serializer, SerializeStruct};
use crate::bbsplus::keys::BBSplusPublicKey;
use crate::utils::util::bbsplus_utils::i2osp;
use super::ciphersuites::BbsCiphersuite;




#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct Generators {
    pub g1_base_point: G1Projective,
    pub q1: G1Projective,
    // pub q2: G1Projective,
    pub message_generators: Vec<G1Projective>
}

impl Serialize for Generators {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
    {
        let result: Vec<String> = self.message_generators.iter()
            .map(|item| hex::encode(item.to_affine().to_compressed())).collect();

        let mut state = serializer.serialize_struct("Generators", 4)?;
        state.serialize_field("BP",
            &hex::encode(self.g1_base_point.to_affine().to_compressed()))?;

        state.serialize_field("Q1",
            &hex::encode(self.q1.to_affine().to_compressed()))?;
        // state.serialize_field("Q2", 
        //     &hex::encode(self.q2.to_affine().to_compressed()))?;

        state.serialize_field("MsgGenerators", &result)?;
        state.end()
    }
}

impl Generators {

    pub fn create<CS>(count: usize) -> Generators
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let generators = create_generators::<CS>(count, Some(CS::API_ID));

        Self { 
            g1_base_point: G1Projective::from_compressed_hex(CS::P1).unwrap(), 
            q1: generators[0].clone(),  
            message_generators: generators[1..].to_vec() 
        }
    }

}



/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-generators-calculation -> generators = create_generators(count, api_id)
/// 
/// # Description
/// Generators creation
/// 
/// # Inputs:
/// * `count` (REQUIRED), unsigned integer. Number of generators to create.
/// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string ("").
/// # Output:
/// * [`Vec<G1Projective>`], an array of generators
///  
pub(crate) fn create_generators<CS>(count: usize, api_id: Option<&[u8]>) -> Vec<G1Projective>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let count = count + 1; // Q1, and generators

    let api_id = api_id.unwrap_or(&[]);

    let seed_dst = [api_id, CS::GENERATOR_SEED_DST].concat();
    let generator_dst = [api_id, CS::GENERATOR_DST].concat();
    let generator_seed = [api_id, CS::GENERATOR_SEED].concat();

    let mut v = vec!(0u8; CS::EXPAND_LEN);
    CS::Expander::expand_message(&[&generator_seed], &[&seed_dst], CS::EXPAND_LEN).unwrap().fill_bytes(&mut v);

    let mut buffer = vec!(0u8; CS::EXPAND_LEN);
    let mut generators = Vec::new();
    for i in 1..count+1 {

        v = [v, i2osp(i, 8)].concat();
        CS::Expander::expand_message(&[&v], &[&seed_dst], CS::EXPAND_LEN).unwrap().fill_bytes(&mut buffer);
        v = buffer.clone();
        let generator = G1Projective::hash::<CS::Expander>(&v, &generator_dst);
        generators.push(generator);
    }
    
    generators
}