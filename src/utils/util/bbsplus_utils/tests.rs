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
use crate::schemes::algorithms::Scheme;
use crate::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
use crate::utils::util::bbsplus_utils::{hash_to_scalar, ScalarExt};
use std::fs;

//h2s - SHA256
#[test]
fn h2s_sha256_1() {
    h2s::<BbsBls12381Sha256>("./fixture_data/fixture_data/bls12-381-sha-256/", "h2s.json");
}
#[test]
fn h2s_sha256_2() {
    h2s::<BbsBls12381Sha256>("./fixture_data/fixture_data/bls12-381-sha-256/", "h2s.json");
}

//h2s - SHAKE256
#[test]
fn h2s_shake256_1() {
    h2s::<BbsBls12381Shake256>("./fixture_data/fixture_data/bls12-381-shake-256/", "h2s.json");
}
#[test]
fn h2s_shake256_2() {
    h2s::<BbsBls12381Shake256>("./fixture_data/fixture_data/bls12-381-shake-256/", "h2s.json");
}

fn h2s<S: Scheme>(pathname: &str, filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let data =
        fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
    let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    println!("{}\n", res["caseName"]);

    let msg_hex = res["message"].as_str().unwrap();
    let dst_hex = res["dst"].as_str().unwrap();
    let scalar_hex_expected = res["scalar"].as_str().unwrap();

    let msg = hex::decode(msg_hex).unwrap();
    let dst = hex::decode(dst_hex).unwrap();

    let scalar = hash_to_scalar::<S::Ciphersuite>(&msg, &dst).unwrap();

    let mut result = true;

    let scalar_hex = hex::encode(scalar.to_bytes_be());

    if scalar_hex != scalar_hex_expected {
        result = false;
        eprintln!("{}", result);

        eprintln!(" Expected scalar: {}", scalar_hex_expected);
        eprintln!(" Computed scalar: {}", scalar_hex);
    }

    assert!(result, "Failed");
}
