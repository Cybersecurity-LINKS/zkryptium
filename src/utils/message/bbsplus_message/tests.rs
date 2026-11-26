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
use crate::utils::message::bbsplus_message::BBSplusMessage;
use std::fs;

//MAP MESSAGE TO SCALAR - SHA256

#[test]
fn map_message_to_scalar_as_hash_sha256() {
    map_message_to_scalar_as_hash::<BbsBls12381Sha256>(
        "./fixture_data/fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json",
    );
}

//MESSAGES TO SCALAR - SHAKE256

#[test]
fn map_message_to_scalar_as_hash_shake256() {
    map_message_to_scalar_as_hash::<BbsBls12381Shake256>(
        "./fixture_data/fixture_data/bls12-381-shake-256/MapMessageToScalarAsHash.json",
    );
}

#[test]
fn messages_to_scalars_sha256() {
    messages_to_scalars::<BbsBls12381Sha256>(
        "./fixture_data/fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json",
    );
}

//MESSAGES TO SCALAR - SHAKE256

#[test]
fn messages_to_scalars_shake256() {
    messages_to_scalars::<BbsBls12381Shake256>(
        "./fixture_data/fixture_data/bls12-381-shake-256/MapMessageToScalarAsHash.json",
    );
}

fn map_message_to_scalar_as_hash<S: Scheme>(filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    eprintln!("{}", json["caseName"]);
    let cases = json["cases"].as_array().unwrap();

    let mut boolean = true;
    for c in cases {
        let msg = &c["message"];

        let msg_hex = hex::decode(msg.as_str().unwrap()).unwrap();

        let out = hex::encode(
            BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(
                &msg_hex,
                <S::Ciphersuite as BbsCiphersuite>::API_ID,
            )
            .unwrap()
            .to_bytes_be(),
        );
        let out_expected = c["scalar"].as_str().unwrap();

        if out != out_expected {
            boolean = false;
        };
    }

    assert!(boolean);
}

fn messages_to_scalars<S: Scheme>(filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    eprintln!("{}", json["caseName"]);
    let mut messages = Vec::new();
    let mut scalars = Vec::new();
    json["cases"].as_array().unwrap().iter().for_each(|v| {
        let msg = v["message"].as_str().unwrap();
        messages.push(hex::decode(msg).unwrap());
        let s = v["scalar"].as_str().unwrap();
        scalars.push(s.to_string());
    });

    let message_scalars = BBSplusMessage::messages_to_scalar::<S::Ciphersuite>(
        &messages,
        <S::Ciphersuite as BbsCiphersuite>::API_ID,
    )
    .unwrap();

    let message_scalars_hex: Vec<String> = message_scalars
        .iter()
        .map(|s| hex::encode(s.to_bytes_be()))
        .collect();

    assert_eq!(scalars, message_scalars_hex);
}
