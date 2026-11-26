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
use crate::keys::pair::KeyPair;
use crate::schemes::algorithms::Scheme;
use crate::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
use crate::{
    bbsplus::{
        keys::{BBSplusPublicKey, BBSplusSecretKey},
        signature::BBSplusSignature,
        test_utils::valid_fixture_bytes,
    },
    errors::Error,
    schemes::{algorithms::BBSplus, generics::Signature},
};
use bls12_381_plus::{G1Projective, Scalar};
use elliptic_curve::group::Curve;
use std::fs;

//MSG SIGNATURE

macro_rules! msg_tests {
    ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
        #[test] fn $n() { msg_signature::<$t>($p, $f); }
    )+)+ }
}

msg_tests! {
    (BbsBls12381Sha256, "./fixture_data/fixture_data/bls12-381-sha-256/"): {
        (msg_signature_sha256_1, "signature/signature001.json"),
        (msg_signature_sha256_2, "signature/signature002.json"),
        (msg_signature_sha256_3, "signature/signature003.json"),
        (msg_signature_sha256_4, "signature/signature004.json"),
        (msg_signature_sha256_5, "signature/signature005.json"),
        (msg_signature_sha256_6, "signature/signature006.json"),
        (msg_signature_sha256_7, "signature/signature007.json"),
        (msg_signature_sha256_8, "signature/signature008.json"),
        (msg_signature_sha256_9, "signature/signature009.json"),
        (msg_signature_sha256_10, "signature/signature010.json"),
    },
    (BbsBls12381Shake256, "./fixture_data/fixture_data/bls12-381-shake-256/"): {
        (msg_signature_shake256_1, "signature/signature001.json"),
        (msg_signature_shake256_2, "signature/signature002.json"),
        (msg_signature_shake256_3, "signature/signature003.json"),
        (msg_signature_shake256_4, "signature/signature004.json"),
        (msg_signature_shake256_5, "signature/signature005.json"),
        (msg_signature_shake256_6, "signature/signature006.json"),
        (msg_signature_shake256_7, "signature/signature007.json"),
        (msg_signature_shake256_8, "signature/signature008.json"),
        (msg_signature_shake256_9, "signature/signature009.json"),
        (msg_signature_shake256_10, "signature/signature010.json"),
    },
}

// FROM_BYTES IDENTITY / ROUND TRIP

const SIG_FIXTURE_DIRS: [&str; 2] = [
    "./fixture_data/fixture_data/bls12-381-sha-256/signature/",
    "./fixture_data/fixture_data/bls12-381-shake-256/signature/",
];

#[test]
fn signature_from_bytes_rejects_identity() {
    let mut bytes = [0u8; BBSplusSignature::BYTES];
    bytes[0..G1Projective::COMPRESSED_BYTES]
        .copy_from_slice(&G1Projective::IDENTITY.to_affine().to_compressed());
    bytes[G1Projective::COMPRESSED_BYTES..].copy_from_slice(&Scalar::ONE.to_be_bytes());
    assert!(matches!(
        BBSplusSignature::from_bytes(&bytes),
        Err(Error::InvalidSignature)
    ));
}

#[test]
fn signature_from_bytes_round_trip() {
    for dir in SIG_FIXTURE_DIRS {
        for sig in valid_fixture_bytes(dir, "signature") {
            let bytes: [u8; BBSplusSignature::BYTES] = sig.clone().try_into().unwrap();
            assert_eq!(
                BBSplusSignature::from_bytes(&bytes).unwrap().to_bytes().to_vec(),
                sig
            );
        }
    }
}

//Update Signature - SHA256
#[test]
fn update_signature_sha256() {
    update_signature::<BbsBls12381Sha256>();
}

//Update Blinded Signature - SHAKE256
#[test]
fn update_signature_shake256() {
    update_signature::<BbsBls12381Shake256>();
}

fn msg_signature<S: Scheme>(pathname: &str, filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let data = fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
    let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    eprintln!("{}", res["caseName"]);

    let header_hex = res["header"].as_str().unwrap();
    let msgs_hex: Vec<String> = res["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| serde_json::from_value(m.clone()).unwrap())
        .collect();
    let SK_hex = res["signerKeyPair"]["secretKey"].as_str().unwrap();
    let PK_hex = res["signerKeyPair"]["publicKey"].as_str().unwrap();
    let SIGNATURE_expected = res["signature"].as_str().unwrap();
    let RESULT_expected = res["result"]["valid"].as_bool().unwrap();

    let header = hex::decode(header_hex).unwrap();
    let SK = BBSplusSecretKey::from_bytes(&hex::decode(SK_hex).unwrap()).unwrap();
    let PK = BBSplusPublicKey::from_bytes(&hex::decode(PK_hex).unwrap()).unwrap();

    let messages: Vec<Vec<u8>> = msgs_hex.iter().map(|m| hex::decode(m).unwrap()).collect();

    let signature =
        Signature::<BBSplus<S::Ciphersuite>>::sign(Some(&messages), &SK, &PK, Some(&header))
            .unwrap();

    let result0 = hex::encode(signature.to_bytes()) == SIGNATURE_expected;

    let result1 = result0 == RESULT_expected;
    if !result1 {
        eprintln!("  SIGN: {}", result1);
        eprintln!("  Expected: {}", SIGNATURE_expected);
        eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));
        assert!(result1, "failed")
    }

    //Verify the signature

    let signature_expected = Signature::<BBSplus<S::Ciphersuite>>::from_bytes(
        &hex::decode(SIGNATURE_expected).unwrap().try_into().unwrap(),
    )
    .unwrap();
    let result2 = signature_expected
        .verify(&PK, Some(&messages), Some(&header))
        .is_ok();
    let result3 = result2 == RESULT_expected;

    if !result3 {
        eprintln!("  VERIFY: {}", result3);
        eprintln!("  Expected: {}", RESULT_expected);
        eprintln!("  Computed: {}", result2);
        assert!(result3, "failed");
    } else {
        eprintln!("  SIGN: {}", result1);
        eprintln!("  Expected: {}", SIGNATURE_expected);
        eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));

        eprintln!("  VERIFY: {}", result3);
        eprintln!("  Expected: {}", RESULT_expected);
        eprintln!("  Computed: {}", result2);
        if !RESULT_expected {
            eprintln!(
                "{} ({})",
                result3,
                res["result"]["reason"].as_str().unwrap()
            );
        }
    }
}

fn update_signature<S: Scheme>()
where
    S::Ciphersuite: BbsCiphersuite,
{
    const IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";
    const msgs: [&str; 3] = [
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6",
        "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90",
    ];
    const header_hex: &str = "11223344556677889900aabbccddeeff";
    let header = hex::decode(header_hex).unwrap();

    let keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
        &hex::decode(IKM).unwrap(),
        Some(&hex::decode(KEY_INFO).unwrap()),
        None,
    )
    .unwrap();

    let sk = keypair.private_key();
    let pk = keypair.public_key();

    let messages: Vec<Vec<u8>> = msgs.iter().map(|m| hex::decode(m).unwrap()).collect();

    let signature =
        Signature::<BBSplus<S::Ciphersuite>>::sign(Some(&messages), sk, pk, Some(&header))
            .unwrap();
    let verify = signature.verify(pk, Some(&messages), Some(&header)).is_ok();

    assert!(verify, "Signature NOT VALID!");

    const new_message: &str =
        "8872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const update_index: usize = 0usize;

    let new_message_bytes = hex::decode(new_message).unwrap();
    let old_message_bytes = messages.get(update_index).unwrap();

    let updated_signature = signature
        .update_signature(
            sk,
            old_message_bytes,
            &new_message_bytes,
            update_index,
            messages.len(),
        )
        .unwrap();

    let mut new_messages = messages.clone();
    new_messages[update_index] = new_message_bytes;

    let verify = updated_signature
        .verify(pk, Some(&new_messages), Some(&header))
        .is_ok();

    assert!(verify, "Signature NOT VALID!");

    const new_message_wrong: &str =
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f01";
    let new_message_bytes_wrong = hex::decode(new_message_wrong).unwrap();
    let mut new_messages_wrong = messages.clone();
    new_messages_wrong[update_index] = new_message_bytes_wrong;

    let verify = updated_signature
        .verify(pk, Some(&new_messages_wrong), Some(&header))
        .is_ok();

    assert!(!verify, "Signature MUST BE NOT VALID!");
}
