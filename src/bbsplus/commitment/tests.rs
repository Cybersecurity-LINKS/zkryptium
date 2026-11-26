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

use std::fs;

use serde_json::Value;
use crate::{
    bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators,
              {commitment::{BBSplusCommitment, BlindFactor, Message}, test_utils::{parse_messages, valid_fixture_bytes}}
    },
    schemes::{
        algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
        generics::Commitment,
    },
    errors::Error,
};

// FROM_BYTES LENGTH VALIDATION
use elliptic_curve::group::Curve;
use bls12_381_plus::{G1Projective, Scalar};
use crate::utils::util::bbsplus_utils::ScalarExt;

const COMMIT_FIXTURE_DIRS: [&str; 2] = [
    "./fixture_data/fixture_data_blind/bls12-381-sha-256/commit/",
    "./fixture_data/fixture_data_blind/bls12-381-shake-256/commit/",
];

#[test]
fn commitment_from_bytes_rejects_identity_commitment() {
    let identity = G1Projective::IDENTITY.to_affine().to_compressed();
    for dir in COMMIT_FIXTURE_DIRS {
        for c in valid_fixture_bytes(dir, "commitmentWithProof") {
            let mut bytes = c.clone();
            bytes[0..48].copy_from_slice(&identity);
            assert!(matches!(
                BBSplusCommitment::from_bytes(&bytes),
                Err(Error::InvalidCommitment)
            ));
        }
    }
}

#[test]
fn commitment_from_bytes_round_trip() {
    for dir in COMMIT_FIXTURE_DIRS {
        for c in valid_fixture_bytes(dir, "commitmentWithProof") {
            assert_eq!(BBSplusCommitment::from_bytes(&c).unwrap().to_bytes(), c);
        }
    }
}

#[test]
fn commitment_from_bytes_rejects_short_input() {
    for len in [0usize, 1, 47] {
        assert!(matches!(
            BBSplusCommitment::from_bytes(&vec![0u8; len]),
            Err(Error::InvalidCommitment)
        ));
    }
}

#[test]
fn commitment_from_bytes_rejects_malformed_proof() {
    for dir in COMMIT_FIXTURE_DIRS {
        for c in valid_fixture_bytes(dir, "commitmentWithProof") {
            // Valid point followed by a missing, too short, or non-aligned proof.
            let mut cases = vec![c[..48].to_vec(), c[..48 + 32].to_vec(), c[..c.len() - 1].to_vec()];
            for extra in [1usize, 31] {
                let mut bytes = c.clone();
                bytes.extend(std::iter::repeat_n(0u8, extra));
                cases.push(bytes);
            }
            for bytes in cases {
                assert!(
                    matches!(BBSplusCommitment::from_bytes(&bytes), Err(Error::InvalidCommitmentProof)),
                    "commitment of {} bytes should be rejected",
                    bytes.len()
                );
            }
        }
    }
}

#[test]
fn commitment_from_bytes_rejects_zero_scalars() {
    // BLIND-01: s^, each m^_i and the challenge must be non-zero.
    for dir in COMMIT_FIXTURE_DIRS {
        for c in valid_fixture_bytes(dir, "commitmentWithProof") {
            for k in 0..(c.len() - 48) / 32 {
                let mut bytes = c.clone();
                bytes[48 + k * 32..48 + (k + 1) * 32].fill(0);
                assert!(matches!(
                    BBSplusCommitment::from_bytes(&bytes),
                    Err(Error::InvalidCommitmentProof)
                ));
            }
        }
    }
}

fn validate_with_generators<S: Scheme>(commitment_with_proof: &[u8], count: usize) -> Result<(), Error>
where
    S::Ciphersuite: BbsCiphersuite,
{
    let api_id = <S::Ciphersuite as BbsCiphersuite>::API_ID_BLIND;
    let blind_generators =
        Generators::create::<S::Ciphersuite>(count, Some(&[b"BLIND_", api_id].concat()));
    Commitment::<BBSplus<S::Ciphersuite>>::deserialize_and_validate_commit(
        Some(commitment_with_proof),
        &blind_generators,
        Some(api_id),
    )
    .map(|_| ())
}

fn check_generators_count<S: Scheme>(dir: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    for c in valid_fixture_bytes(dir, "commitmentWithProof") {
        // M + 1 blind generators, with M = number of m^ in the proof.
        let expected = (c.len() - 48) / 32 - 1;
        assert!(validate_with_generators::<S>(&c, expected).is_ok());
        for count in [expected - 1, expected + 1, expected + 2] {
            assert!(matches!(
                validate_with_generators::<S>(&c, count),
                Err(Error::InvalidNumberOfGenerators)
            ));
        }
    }
}

#[test]
fn deserialize_and_validate_commit_requires_exact_generators_count() {
    // BLIND-02: draft 05 §4.1.2 step 5, the count must be exactly M + 1.
    check_generators_count::<BbsBls12381Sha256>(COMMIT_FIXTURE_DIRS[0]);
    check_generators_count::<BbsBls12381Shake256>(COMMIT_FIXTURE_DIRS[1]);
}

#[test]
fn raw_message_not_a_scalar_is_rejected() {
    // BLIND-06: a RAW value >= r is reported as MapMessageToScalarError.
    let api_id = <BbsBls12381Sha256 as Scheme>::Ciphersuite::API_ID_BLIND;
    for v in [vec![0xffu8; 32], vec![0x01u8; 33]] {
        assert!(matches!(
            super::messages_to_scalar::<<BbsBls12381Sha256 as Scheme>::Ciphersuite>(
                &[Message::Raw(v)],
                Some(api_id)
            ),
            Err(Error::MapMessageToScalarError)
        ));
    }
    // Leading zeros are fine: the value is what matters.
    let mut padded = vec![0u8; 40];
    padded[39] = 5;
    assert!(super::messages_to_scalar::<<BbsBls12381Sha256 as Scheme>::Ciphersuite>(
        &[Message::Raw(padded)],
        Some(api_id)
    )
    .is_ok());
}

fn check_rejects_tampered_commitment<S: Scheme>(dir: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    for c in valid_fixture_bytes(dir, "commitmentWithProof") {
        let generators_count = (c.len() - 48) / 32 - 1;

        // Each proof scalar (s^, m^_1..m^_M, challenge) replaced by a different valid scalar.
        for k in 0..(c.len() - 48) / 32 {
            let range = 48 + k * 32..48 + (k + 1) * 32;
            let scalar = Scalar::from_bytes_be(&c[range.clone()]).unwrap() + Scalar::ONE;
            let mut bytes = c.clone();
            bytes[range].copy_from_slice(&scalar.to_be_bytes());
            assert!(
                matches!(
                    validate_with_generators::<S>(&bytes, generators_count),
                    Err(Error::InvalidCommitmentProof)
                ),
                "proof scalar {k} tampered"
            );
        }

        // Commitment replaced by a different valid point.
        let mut bytes = c.clone();
        bytes[..48].copy_from_slice(&G1Projective::GENERATOR.to_affine().to_compressed());
        assert!(matches!(
            validate_with_generators::<S>(&bytes, generators_count),
            Err(Error::InvalidCommitmentProof)
        ));

        // Valid proof checked against the generators of another api_id.
        let other_generators = Generators::create::<S::Ciphersuite>(generators_count, Some(b"BLIND_other"));
        assert!(Commitment::<BBSplus<S::Ciphersuite>>::deserialize_and_validate_commit(
            Some(&c),
            &other_generators,
            Some(<S::Ciphersuite as BbsCiphersuite>::API_ID_BLIND),
        )
        .is_err());
    }
}

#[test]
fn deserialize_and_validate_commit_rejects_tampered_commitment() {
    // BLIND-08: tampered proof or commitment must fail CoreCommitVerify.
    check_rejects_tampered_commitment::<BbsBls12381Sha256>(COMMIT_FIXTURE_DIRS[0]);
    check_rejects_tampered_commitment::<BbsBls12381Shake256>(COMMIT_FIXTURE_DIRS[1]);
}

#[test]
fn blind_secrets_are_zeroized() {
    use crate::bbsplus::proof::AddZkpInfo;
    use bls12_381_plus::Scalar;
    use zeroize::{Zeroize, ZeroizeOnDrop};
    fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
    zeroize_on_drop::<BlindFactor>();
    zeroize_on_drop::<AddZkpInfo>();

    let mut blind = BlindFactor::random();
    blind.zeroize();
    assert_eq!(blind.0, Scalar::ZERO);

    let mut info = AddZkpInfo {
        committed_message_scalars: vec![Scalar::ONE; 3],
        commitment_rands: vec![Scalar::ONE; 3],
    };
    info.zeroize();
    assert!(info.committed_message_scalars.is_empty() && info.commitment_rands.is_empty());
}

#[test]
fn blind_factor_debug_is_redacted() {
    // BLIND-03: the secret_prover_blind must not leak through {:?}.
    let blind = BlindFactor::from_bytes(&[0x11; 32]).unwrap();
    let debug = format!("{:?}", blind);
    assert_eq!(debug, "BlindFactor(<redacted>)");
    assert!(!debug.contains("11"));
}

macro_rules! commit_tests {
    ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
        #[test] fn $n() { commit::<$t>($p, $f); }
    )+)+ }
}

commit_tests! {
    (BbsBls12381Sha256, "./fixture_data/fixture_data_blind/bls12-381-sha-256/"): {
        (commit_sha256_1, "commit/commit001.json"),
        (commit_sha256_2, "commit/commit002.json"),
    },
    (BbsBls12381Shake256, "./fixture_data/fixture_data_blind/bls12-381-shake-256/"): {
        (commit_shake256_1, "commit/commit001.json"),
        (commit_shake256_2, "commit/commit002.json"),
    },
}

fn commit<S: Scheme>(pathname: &str, filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let data = fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
    let proof_json: Value = serde_json::from_str(&data).expect("Unable to parse");
    println!("{}", proof_json["caseName"]);

    let blind_messages = parse_messages(&proof_json["blindMessages"]);

    let prover_blind = proof_json["proverBlind"].as_str().unwrap();
    let commitment_with_proof = proof_json["commitmentWithProof"].as_str().unwrap();

    let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

    let (commitment_with_proof_result, secret) =
            Commitment::<BBSplus<S::Ciphersuite>>::commit(Some(&blind_messages)).unwrap();

    let commitment_with_proof_result_oct = commitment_with_proof_result.to_bytes();
    assert_eq!(
        hex::encode(&commitment_with_proof_result_oct),
        commitment_with_proof
    );

    assert_eq!(hex::encode(secret.to_bytes()), prover_blind);

    let blind_generators = Generators::create::<S::Ciphersuite>(
        blind_messages.len() + 1,
            Some(&[b"BLIND_", <S::Ciphersuite as BbsCiphersuite>::API_ID_BLIND].concat()),
    );

    let result = Commitment::<BBSplus<S::Ciphersuite>>::deserialize_and_validate_commit(
        Some(&commitment_with_proof_result_oct),
        &blind_generators,
        Some(<S::Ciphersuite as BbsCiphersuite>::API_ID_BLIND),
    ).is_ok();

    assert_eq!(result, expected_result);
    }
