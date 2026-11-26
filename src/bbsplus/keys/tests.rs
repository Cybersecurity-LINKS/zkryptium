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
use crate::{keys::pair::KeyPair, schemes::algorithms::BBSplus};
use std::fs;

// The secret key must not leak through {:?}, also inside a KeyPair, and is zeroized on drop.
#[test]
fn secret_key_debug_is_redacted_and_zeroized() {
    use crate::bbsplus::keys::BBSplusSecretKey;
    use bls12_381_plus::Scalar;
    use zeroize::{Zeroize, ZeroizeOnDrop};
    fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
    zeroize_on_drop::<BBSplusSecretKey>();

    let keypair = KeyPair::<BbsBls12381Sha256>::generate(&[7u8; 32], None, None).unwrap();
    let sk_hex = hex::encode(keypair.private_key().to_bytes());
    for debug in [format!("{:?}", keypair.private_key()), format!("{:?}", keypair)] {
        assert!(debug.contains("BBSplusSecretKey(<redacted>)"), "{debug}");
        assert!(!debug.contains(&sk_hex[..16]), "{debug}");
    }

    let mut sk = keypair.private_key().clone();
    sk.zeroize();
    assert_eq!(sk.0, Scalar::ZERO);
}

// FROM_BYTES LENGTH VALIDATION

use crate::{bbsplus::{keys::BBSplusPublicKey, test_utils::valid_fixture_bytes}, errors::Error};
use bls12_381_plus::G2Projective;
use elliptic_curve::group::Curve;

const PK_FIXTURE_DIRS: [&str; 2] = [
    "./fixture_data/fixture_data/bls12-381-sha-256/proof/",
    "./fixture_data/fixture_data/bls12-381-shake-256/proof/",
];

fn assert_pk_rejected(bytes: &[u8]) {
    assert!(
        matches!(BBSplusPublicKey::from_bytes(bytes), Err(Error::KeyDeserializationError)),
        "public key of {} bytes should be rejected",
        bytes.len()
    );
}

#[test]
fn public_key_from_bytes_rejects_identity() {
    let identity = G2Projective::IDENTITY.to_affine().to_compressed();
    assert_pk_rejected(&identity);
}

#[test]
fn public_key_from_coordinates_rejects_identity() {
    let uncompressed = G2Projective::IDENTITY.to_affine().to_uncompressed();
    let (x, y) = uncompressed.split_at(BBSplusPublicKey::COORDINATE_LEN);
    let x: [u8; BBSplusPublicKey::COORDINATE_LEN] = x.try_into().unwrap();
    let y: [u8; BBSplusPublicKey::COORDINATE_LEN] = y.try_into().unwrap();
    assert!(matches!(
        BBSplusPublicKey::from_coordinates(&x, &y),
        Err(Error::KeyDeserializationError)
    ));
}

#[test]
fn public_key_from_bytes_round_trip() {
    for dir in PK_FIXTURE_DIRS {
        for pk in valid_fixture_bytes(dir, "signerPublicKey") {
            assert_eq!(BBSplusPublicKey::from_bytes(&pk).unwrap().to_bytes().to_vec(), pk);
        }
    }
}

#[test]
fn public_key_from_bytes_rejects_invalid_lengths() {
    for len in [0usize, 1, 48, 95, 97, 192] {
        assert_pk_rejected(&vec![0u8; len]);
    }
    for dir in PK_FIXTURE_DIRS {
        for pk in valid_fixture_bytes(dir, "signerPublicKey") {
            assert_pk_rejected(&pk[..95]);
            for extra in [1usize, 32] {
                let mut bytes = pk.clone();
                bytes.extend(std::iter::repeat_n(0u8, extra));
                assert_pk_rejected(&bytes);
            }
        }
    }
}

//KEYPAIR - SHA256

#[test]
fn keypair_sha256() {
    key_pair_gen::<BbsBls12381Sha256>("./fixture_data/fixture_data/bls12-381-sha-256/keypair.json");
}

//KEYPAIR - SHAKE256

#[test]
fn keypair_shake256() {
    key_pair_gen::<BbsBls12381Shake256>("./fixture_data/fixture_data/bls12-381-shake-256/keypair.json");
}

fn key_pair_gen<S: Scheme>(filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    eprintln!("Key Pair");
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let data_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    let IKM = data_json["keyMaterial"].as_str().unwrap();
    let KEY_INFO = data_json["keyInfo"].as_str().unwrap();
    let KEY_DST = data_json["keyDst"].as_str().unwrap();
    let SK_expected = data_json["keyPair"]["secretKey"].as_str().unwrap();
    let PK_expected = data_json["keyPair"]["publicKey"].as_str().unwrap();

    let keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
        &hex::decode(IKM).unwrap(),
        Some(&hex::decode(KEY_INFO).unwrap()),
        Some(&hex::decode(KEY_DST).unwrap()),
    )
    .unwrap();

    let sk = keypair.private_key().encode();
    let pk = keypair.public_key().encode();

    let result1 = sk == SK_expected;

    if !result1 {
        println!("      keyGen:        {}", result1);
        println!("      Expected key:  {}", SK_expected);
        println!("      Generated key: {}", sk);
    }

    let result2 = pk == PK_expected;

    if !result2 {
        println!("      skToPk:        {}", result2);
        println!("      Expected key:  {}", PK_expected);
        println!("      Generated key: {}", pk);
    }
    let result = result1 && result2;

    assert!(result, "Failed");
}
