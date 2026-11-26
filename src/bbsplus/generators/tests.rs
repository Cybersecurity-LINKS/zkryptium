// Copyright 2026 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::bbsplus::ciphersuites::BbsCiphersuite;
use crate::bbsplus::generators::Generators;
use crate::schemes::algorithms::Scheme;
use crate::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
use elliptic_curve::group::Curve;
use std::fs;

//GENERATORS - SHA256
#[test]
fn message_generators_sha256() {
    message_generators::<BbsBls12381Sha256>("./fixture_data/fixture_data/bls12-381-sha-256/generators.json");
}

//GENERATORS - SHAKE256

#[test]
fn message_generators_shake256() {
    message_generators::<BbsBls12381Shake256>(
        "./fixture_data/fixture_data/bls12-381-shake-256/generators.json",
    );
}

fn message_generators<S: Scheme>(filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
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

    if !result {
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

    assert!(result);
}
