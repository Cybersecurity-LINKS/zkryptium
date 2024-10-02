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

use alloc::{vec::Vec, string::String};
use super::ciphersuites::BbsCiphersuite;
use crate::utils::util::bbsplus_utils::i2osp;
use bls12_381_plus::G1Projective;
use elliptic_curve::group::Curve;
use elliptic_curve::hash2curve::{ExpandMsg, Expander};
use serde::ser::{SerializeStruct, Serializer};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct Generators {
    pub g1_base_point: G1Projective,
    pub values: Vec<G1Projective>,
}

impl Serialize for Generators {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let result: Vec<String> = self
            .values
            .iter()
            .map(|item| hex::encode(item.to_affine().to_compressed()))
            .collect();

        let mut state = serializer.serialize_struct("Generators", 4)?;
        state.serialize_field(
            "BP",
            &hex::encode(self.g1_base_point.to_affine().to_compressed()),
        )?;

        state.serialize_field("Generators", &result)?;
        state.end()
    }
}

impl Generators {
    /// # Description
    /// Create Generators an P1 (A fixed point in the G1 subgroup)
    ///
    /// # Inputs:
    /// * `count` (REQUIRED), unsigned integer. Number of generators to create.
    /// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string ("").
    ///
    /// # Output:
    /// * [`Generators`], containing an array of generators and P1
    ///  
    pub fn create<CS>(count: usize, api_id: Option<&[u8]>) -> Generators
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let generators = create_generators::<CS>(count, api_id);

        Self {
            g1_base_point: G1Projective::from_compressed_hex(CS::P1).unwrap(),
            values: generators[0..].to_vec(),
        }
    }

    /// Utility to append one list of Generators to another.
    /// # Panics
    /// Panics if the Generators have different base points.
    pub(crate) fn append(mut self, other: Self) -> Self {
        assert_eq!(self.g1_base_point, other.g1_base_point);
        self.values.extend(other.values);
        self
    }
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-generators-calculation
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
fn create_generators<CS>(count: usize, api_id: Option<&[u8]>) -> Vec<G1Projective>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let api_id = api_id.unwrap_or(&[]);

    let seed_dst = [api_id, CS::GENERATOR_SEED_DST].concat();
    let generator_dst = [api_id, CS::GENERATOR_DST].concat();
    let generator_seed = [api_id, CS::GENERATOR_SEED].concat();

    let mut v = vec![0u8; CS::EXPAND_LEN];
    CS::Expander::expand_message(&[&generator_seed], &[&seed_dst], CS::EXPAND_LEN)
        .unwrap()
        .fill_bytes(&mut v);

    let mut buffer = vec![0u8; CS::EXPAND_LEN];
    let mut generators = Vec::new();
    for i in 1..count + 1 {
        v = [&*v, &i2osp::<8>(i)].concat();
        CS::Expander::expand_message(&[&v], &[&seed_dst], CS::EXPAND_LEN)
            .unwrap()
            .fill_bytes(&mut buffer);
        v = buffer.clone();
        let generator = G1Projective::hash::<CS::Expander>(&v, &generator_dst);
        generators.push(generator);
    }

    generators
}

#[cfg(test)]
mod tests {

    use crate::bbsplus::ciphersuites::BbsCiphersuite;
    use crate::bbsplus::generators::Generators;
    use crate::schemes::algorithms::Scheme;
    use crate::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
    use elliptic_curve::{group::Curve, hash2curve::ExpandMsg};
    use std::fs;

    //GENERATORS - SHA256
    #[test]
    fn message_generators_sha256() {
        message_generators::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/generators.json");
    }

    //GENERATORS - SHAKE256

    #[test]
    fn message_generators_shake256() {
        message_generators::<BbsBls12381Shake256>(
            "./fixture_data/bls12-381-shake-256/generators.json",
        );
    }

    fn message_generators<S: Scheme>(filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string(filename).expect("Unable to read file");
        let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        eprintln!("Message Generators");

        let mut generators_expected: Vec<&str> = Vec::new();
        for g in res["MsgGenerators"].as_array().unwrap() {
            generators_expected.push(g.as_str().unwrap());
        }

        println!("{}", generators_expected.len());
        let generators = Generators::create::<S::Ciphersuite>(
            generators_expected.len() + 1,
            Some(<S::Ciphersuite as BbsCiphersuite>::API_ID),
        );
        println!("{}", generators.values.len());

        let Q1 = generators.values[0];
        let message_generators = &generators.values[1..];

        let expected_BP = res["P1"].as_str().unwrap();

        //check BP
        let BP = hex::encode(generators.g1_base_point.to_affine().to_compressed());

        let mut result = BP == expected_BP;
        // println!("{}", result);

        if result == false {
            eprintln!("{}", result);
            eprintln!("  GENERATOR BP: {}", result);
            eprintln!("  Expected: {}", expected_BP);
            eprintln!("  Computed: {}", BP);
        }

        let expected_Q1 = res["Q1"].as_str().unwrap();
        let Q1 = hex::encode(Q1.to_compressed());

        if expected_Q1 != Q1 {
            result = false;
            eprintln!("  GENERATOR Q1: {}", result);
            eprintln!("  Expected: {}", expected_Q1);
            eprintln!("  Computed: {}", Q1);
        }

        generators_expected
            .iter()
            .enumerate()
            .for_each(|(i, expected_g)| {
                let g = hex::encode(
                    message_generators
                        .get(i)
                        .expect("index overflow")
                        .to_affine()
                        .to_compressed(),
                );
                if *expected_g != g {
                    result = false;
                    eprintln!("  GENERATOR {}: {}", i, result);
                    eprintln!("  Expected: {}", *expected_g);
                    eprintln!("  Computed: {}", g);
                }
            });

        assert_eq!(result, true);
    }
}
