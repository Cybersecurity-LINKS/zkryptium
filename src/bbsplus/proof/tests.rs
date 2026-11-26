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

use crate::{
    bbsplus::{
        ciphersuites::BbsCiphersuite, keys::BBSplusPublicKey,
        proof::seeded_random_scalars
    },
    schemes::{
        algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
        generics::{PoKSignature, Signature},
    },
    utils::util::bbsplus_utils::{get_messages_vec, ScalarExt},
};

#[cfg(feature = "bbsplus_blind")]
use crate::{
    bbsplus::{
        commitment::{BlindFactor, Message},
        generators::Generators,
        proof::{
            core_blind_proof_gen, AddZkpInfo, BBSplusBlindPoKSignature, BlindProofGenInput,
            BlindProofVerifyInput, Disclosure,
        },
        signature::BBSplusSignature,
    },
    schemes::generics::BlindPoKSignature,
    utils::message::bbsplus_message::BBSplusMessage,
};
#[cfg(feature = "bbsplus_blind")]
use crate::bbsplus::test_utils::{parse_disclosures, parse_messages};

// BBS-02: disclosed messages and indexes come from the Prover presentation. A different
// count or a repeated index must be an error (it used to panic in the multi-exponentiation),
// and unsorted indexes must keep each message paired with its index.
#[test]
fn proof_verify_disclosed_messages_and_indexes() {
    use crate::{errors::Error, keys::pair::KeyPair};
    type S = BbsBls12381Sha256;

    let keypair = KeyPair::<S>::generate(&[7u8; 32], None, None).unwrap();
    let (sk, pk) = (keypair.private_key(), keypair.public_key());
    let messages: Vec<Vec<u8>> = vec![b"m0".to_vec(), b"m1".to_vec(), b"m2".to_vec()];
    let signature = Signature::<S>::sign(Some(&messages), sk, pk, None).unwrap().to_bytes();
    let proof =
        PoKSignature::<S>::proof_gen(pk, &signature, None, None, Some(&messages), Some(&[0, 2])).unwrap();
    let verify = |msgs: &[Vec<u8>], idx: &[usize]| proof.proof_verify(pk, Some(msgs), Some(idx), None, None);
    let (m0, m2) = (messages[0].clone(), messages[2].clone());

    assert!(verify(&[m0.clone(), m2.clone()], &[0, 2]).is_ok());
    // Same pairs, indexes not in ascending order.
    assert!(verify(&[m2.clone(), m0.clone()], &[2, 0]).is_ok());
    // Different counts, in both directions.
    assert!(matches!(verify(std::slice::from_ref(&m0), &[0, 2]), Err(Error::PoKSVerificationError(_))));
    assert!(matches!(verify(&[m0.clone(), m2.clone()], &[0]), Err(Error::PoKSVerificationError(_))));
    // Repeated index.
    assert!(matches!(verify(&[m0.clone(), m0], &[0, 0]), Err(Error::PoKSVerificationError(_))));
}

// Forgery with Abar = Bbar = Identity_G1: the pairing check becomes trivial and the
// Fiat-Shamir part is a Schnorr proof on D alone, which anyone can produce for any
// disclosed messages. Such a proof must be rejected however it is obtained (here via serde).
#[test]
fn proof_verify_rejects_identity_abar_bbar_forgery() {
    use crate::bbsplus::proof::{proof_challenge_calculate, ProofInitRes};
    use crate::utils::message::bbsplus_message::BBSplusMessage;
    use crate::{bbsplus::generators::Generators, keys::pair::KeyPair,
                utils::util::bbsplus_utils::calculate_domain};
    use crate::errors::Error;
    use bls12_381_plus::{G1Projective, Scalar};
    use ff::Field;
    type S = BbsBls12381Sha256;
    type CS = <S as Scheme>::Ciphersuite;

    // Honest issuer key: the forger never sees sk nor any signature.
    let keypair = KeyPair::<S>::generate(&[9u8; 32], None, None).unwrap();
    let pk = keypair.public_key();
    let L = 3;
    let disclosed_indexes = vec![0usize, 2];
    let disclosed_messages: Vec<Vec<u8>> = vec![b"admin".to_vec(), b"forged".to_vec()];
    let msg_scalars =
        BBSplusMessage::messages_to_scalar::<CS>(&disclosed_messages, CS::API_ID).unwrap();

    let generators = Generators::create::<CS>(L + 1, Some(CS::API_ID));
    let domain = calculate_domain::<CS>(pk, &generators, None, Some(CS::API_ID)).unwrap();
    let mut Bv = generators.g1_base_point + generators.values[0] * domain;
    for (i, m) in disclosed_indexes.iter().zip(&msg_scalars) {
        Bv += generators.values[i + 1] * m.value;
    }

    let mut rng = rand::rng();
    let (delta, alpha, tau, gamma) = (
        Scalar::random(&mut rng), Scalar::random(&mut rng), Scalar::random(&mut rng),
        Scalar::random(&mut rng),
    );
    let D = Bv * delta;
    let T1 = D * alpha;
    let T2 = Bv * tau + generators.values[2] * gamma; // undisclosed index 1
    let init_res = ProofInitRes {
        Abar: G1Projective::IDENTITY,
        Bbar: G1Projective::IDENTITY,
        D,
        T1,
        T2,
        domain,
        L,
        disclosed_indexes: disclosed_indexes.clone(),
        disclosed_messages: msg_scalars,
        undisclosed_messages: None,
        e: None,
        random_scalars: None,
    };
    let c = proof_challenge_calculate::<CS>(&init_res, None, Some(CS::API_ID)).unwrap();
    let forged = BBSplusPoKSignature {
        Abar: G1Projective::IDENTITY,
        Bbar: G1Projective::IDENTITY,
        D,
        e_cap: Scalar::random(&mut rng),
        r1_cap: alpha,
        r3_cap: (tau - c) * delta.invert().unwrap(),
        m_cap: vec![gamma],
        challenge: c,
    };

    // The byte parser rejects it (identity check of octets_to_proof)...
    assert!(BBSplusPoKSignature::from_bytes(&forged.to_bytes()).is_err());
    // ...but serde decoding accepts the identity, so verification must reject it.
    let json = serde_json::to_string(&PoKSignature::<S>::BBSplus(forged)).unwrap();
    let proof = serde_json::from_str::<PoKSignature<S>>(&json).unwrap();
    let res = proof.proof_verify(
        pk, Some(&disclosed_messages), Some(&disclosed_indexes), None, None,
    );
    assert!(matches!(res, Err(Error::InvalidProofOfKnowledgeSignature)), "{res:?}");
}

// Identity public key or signature point decoded via serde must be rejected by the
// verification, as octets_to_pubkey / octets_to_signature do.
#[test]
fn verify_rejects_identity_pk_and_signature_from_serde() {
    use crate::{bbsplus::keys::BBSplusPublicKey, keys::pair::KeyPair};
    use bls12_381_plus::G2Projective;
    type S = BbsBls12381Sha256;

    let keypair = KeyPair::<S>::generate(&[11u8; 32], None, None).unwrap();
    let (sk, pk) = (keypair.private_key(), keypair.public_key());
    let messages: Vec<Vec<u8>> = vec![b"m0".to_vec(), b"m1".to_vec()];
    let signature = Signature::<S>::sign(Some(&messages), sk, pk, None).unwrap();
    let proof = PoKSignature::<S>::proof_gen(
        pk, &signature.to_bytes(), None, None, Some(&messages), Some(&[0]),
    ).unwrap();

    let identity_pk: BBSplusPublicKey = serde_json::from_str(
        &serde_json::to_string(&BBSplusPublicKey(G2Projective::IDENTITY)).unwrap(),
    ).unwrap();
    assert!(matches!(
        signature.verify(&identity_pk, Some(&messages), None),
        Err(Error::KeyDeserializationError)
    ));
    assert!(matches!(
        proof.proof_verify(&identity_pk, Some(&messages[..1]), Some(&[0]), None, None),
        Err(Error::KeyDeserializationError)
    ));

    let mut json: serde_json::Value = serde_json::to_value(&signature).unwrap();
    json["BBSplus"]["A"] = serde_json::to_value(G1Projective::IDENTITY).unwrap();
    let identity_sig: Signature<S> = serde_json::from_value(json).unwrap();
    assert!(matches!(
        identity_sig.verify(pk, Some(&messages), None),
        Err(Error::InvalidSignature)
    ));
}

// The `_Unreachable` variant of the generic enums must not be decodable: the accessors
// (`to_bbsplus_proof`, ...) panic on it, so `{"_Unreachable":null}` made any verification
// panic (found by the `serde` fuzz target).
#[test]
fn unreachable_variant_is_not_deserializable() {
    use crate::schemes::generics::ZKPoK;
    type S = BbsBls12381Sha256;
    let json = r#"{"_Unreachable":null}"#;
    assert!(serde_json::from_str::<PoKSignature<S>>(json).is_err());
    assert!(serde_json::from_str::<Signature<S>>(json).is_err());
    assert!(serde_json::from_str::<ZKPoK<S>>(json).is_err());
    #[cfg(feature = "bbsplus_blind")]
    {
        use crate::schemes::generics::{BlindPoKSignature, BlindSignature, Commitment};
        assert!(serde_json::from_str::<BlindPoKSignature<S>>(json).is_err());
        assert!(serde_json::from_str::<BlindSignature<S>>(json).is_err());
        assert!(serde_json::from_str::<Commitment<S>>(json).is_err());
    }
}

//mocked_rng - SHA256 - UPDATED
#[test]
fn mocked_rng_sha256() {
    mocked_rng::<BbsBls12381Sha256>(
        "./fixture_data/fixture_data/bls12-381-sha-256/",
        "mockedRng.json"
    );
}

//mocked_rng - SHAKE256 - UPDATED
#[test]
fn mocked_rng_shake256() {
    mocked_rng::<BbsBls12381Shake256>(
        "./fixture_data/fixture_data/bls12-381-shake-256/",
        "mockedRng.json"
    );
}

// FROM_BYTES LENGTH VALIDATION
use crate::{bbsplus::{proof::{BBSplusPoKSignature, BBSplusZKPoK}, test_utils::valid_fixture_bytes},
            errors::Error};
use bls12_381_plus::{G1Projective, Scalar};
use elliptic_curve::group::Curve;

const POK_FIXTURE_DIRS: [&str; 2] = [
    "./fixture_data/fixture_data/bls12-381-sha-256/proof/",
    "./fixture_data/fixture_data/bls12-381-shake-256/proof/",
];

fn assert_pok_rejected(bytes: &[u8]) {
    assert!(
        matches!(
            BBSplusPoKSignature::from_bytes(bytes),
            Err(Error::InvalidProofOfKnowledgeSignature)
        ),
        "proof of {} bytes should be rejected",
        bytes.len()
    );
}

#[test]
fn pok_from_bytes_rejects_identity_points() {
    let identity = G1Projective::IDENTITY.to_affine().to_compressed();
    for dir in POK_FIXTURE_DIRS {
        for proof in valid_fixture_bytes(dir, "proof") {
            for offset in [0usize, 48, 96] {
                let mut bytes = proof.clone();
                bytes[offset..offset + 48].copy_from_slice(&identity);
                assert_pok_rejected(&bytes);
            }
        }
    }
}

#[test]
fn pok_from_bytes_round_trip() {
    for dir in POK_FIXTURE_DIRS {
        for proof in valid_fixture_bytes(dir, "proof") {
            let parsed = BBSplusPoKSignature::from_bytes(&proof).unwrap();
            assert_eq!(parsed.to_bytes(), proof);
        }
    }
}

#[test]
fn pok_from_bytes_rejects_trailing_bytes() {
    for dir in POK_FIXTURE_DIRS {
        for proof in valid_fixture_bytes(dir, "proof") {
            for extra in [1usize, 16, 31] {
                let mut bytes = proof.clone();
                bytes.extend(std::iter::repeat_n(0u8, extra));
                assert_pok_rejected(&bytes);
            }
        }
    }
}

#[test]
fn pok_from_bytes_rejects_truncated_input() {
    for dir in POK_FIXTURE_DIRS {
        for proof in valid_fixture_bytes(dir, "proof") {
            for cut in [1usize, 31] {
                assert_pok_rejected(&proof[..proof.len() - cut]);
            }
        }
    }
}

#[test]
fn pok_from_bytes_rejects_invalid_lengths() {
    for len in [0usize, 10, 48, 144, 239, 240, 271, 272 + 16, 304 + 1] {
        assert_pok_rejected(&vec![0u8; len]);
    }
}

#[test]
fn pok_from_bytes_extra_scalar_is_parsed_as_message() {
    // Appending a whole scalar is a well-formed encoding with one more
    // undisclosed message; it is rejected at verification time, not parsing.
    let proof = &valid_fixture_bytes(POK_FIXTURE_DIRS[0], "proof")[0];
    let parsed = BBSplusPoKSignature::from_bytes(proof).unwrap();
    let mut bytes = proof.clone();
    bytes.extend([0u8; 32]);
    let extended = BBSplusPoKSignature::from_bytes(&bytes).unwrap();
    assert_eq!(extended.m_cap.len(), parsed.m_cap.len() + 1);
}

fn assert_zkpok_rejected(bytes: &[u8]) {
    assert!(
        matches!(
            BBSplusZKPoK::from_bytes(bytes),
            Err(Error::InvalidCommitmentProof)
        ),
        "ZKPoK of {} bytes should be rejected",
        bytes.len()
    );
}

#[test]
fn zkpok_from_bytes_round_trip() {
    for m in 0..3u64 {
        let zkpok = BBSplusZKPoK::new(
            Scalar::from(7u64),
            (0..m).map(|i| Scalar::from(100 + i)).collect(),
            Scalar::from(42u64),
        );
        let bytes = zkpok.to_bytes();
        assert_eq!(bytes.len(), 64 + 32 * m as usize);
        assert_eq!(BBSplusZKPoK::from_bytes(&bytes).unwrap(), zkpok);
    }
}

#[test]
fn zkpok_from_bytes_rejects_zero_scalars() {
    // s^, each m^_i and the challenge must all be non-zero (octets_to_commitment_with_proof step 13).
    let zkpok = BBSplusZKPoK::new(
        Scalar::from(7u64),
        vec![Scalar::from(100u64), Scalar::from(101u64)],
        Scalar::from(42u64),
    );
    let bytes = zkpok.to_bytes();
    for k in 0..bytes.len() / 32 {
        let mut tampered = bytes.clone();
        tampered[k * 32..(k + 1) * 32].fill(0);
        assert_zkpok_rejected(&tampered);
    }
}

#[test]
fn zkpok_from_bytes_rejects_invalid_lengths() {
    for len in [0usize, 1, 31, 32, 63, 65, 95, 96 + 31] {
        assert_zkpok_rejected(&vec![0u8; len]);
    }

    let valid = BBSplusZKPoK::new(
        Scalar::from(7u64),
        vec![Scalar::from(9u64)],
        Scalar::from(42u64)
    ).to_bytes();
    for extra in [1usize, 31] {
        let mut bytes = valid.clone();
        bytes.extend(std::iter::repeat_n(0u8, extra));
        assert_zkpok_rejected(&bytes);
    }
}

#[test]
fn zkpok_from_bytes_rejects_non_canonical_scalars() {
    let valid = BBSplusZKPoK::new(Scalar::from(7u64), vec![Scalar::from(9u64)], Scalar::from(42u64))
        .to_bytes();
    // 0xff..ff is larger than the group order, so it is not a valid scalar encoding.
    for start in (0..valid.len()).step_by(Scalar::BYTES) {
        let mut bytes = valid.clone();
        bytes[start..start + Scalar::BYTES].fill(0xff);
        assert_zkpok_rejected(&bytes);
    }
}

//SIGNATURE POK

macro_rules! proof_tests {
    ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
        #[test] fn $n() { proof_check::<$t>($p, $f); }
    )+)+ }
}

proof_tests! {
    (BbsBls12381Sha256, "./fixture_data/fixture_data/bls12-381-sha-256/"): {
        (proof_check_sha256_1, "proof/proof001.json"),
        (proof_check_sha256_2, "proof/proof002.json"),
        (proof_check_sha256_3, "proof/proof003.json"),
        (proof_check_sha256_4, "proof/proof004.json"),
        (proof_check_sha256_5, "proof/proof005.json"),
        (proof_check_sha256_6, "proof/proof006.json"),
        (proof_check_sha256_7, "proof/proof007.json"),
        (proof_check_sha256_8, "proof/proof008.json"),
        (proof_check_sha256_9, "proof/proof009.json"),
        (proof_check_sha256_10, "proof/proof010.json"),
        (proof_check_sha256_11, "proof/proof011.json"),
        (proof_check_sha256_12, "proof/proof012.json"),
        (proof_check_sha256_13, "proof/proof013.json"),
        (proof_check_sha256_14, "proof/proof014.json"),
        (proof_check_sha256_15, "proof/proof015.json"),
    },
    (BbsBls12381Shake256, "./fixture_data/fixture_data/bls12-381-shake-256/"): {
        (proof_check_shake256_1, "proof/proof001.json"),
        (proof_check_shake256_2, "proof/proof002.json"),
        (proof_check_shake256_3, "proof/proof003.json"),
        (proof_check_shake256_4, "proof/proof004.json"),
        (proof_check_shake256_5, "proof/proof005.json"),
        (proof_check_shake256_6, "proof/proof006.json"),
        (proof_check_shake256_7, "proof/proof007.json"),
        (proof_check_shake256_8, "proof/proof008.json"),
        (proof_check_shake256_9, "proof/proof009.json"),
        (proof_check_shake256_10, "proof/proof010.json"),
        (proof_check_shake256_11, "proof/proof011.json"),
        (proof_check_shake256_12, "proof/proof012.json"),
        (proof_check_shake256_13, "proof/proof013.json"),
        (proof_check_shake256_14, "proof/proof014.json"),
        (proof_check_shake256_15, "proof/proof015.json"),
    },
}

// BLIND PROOF OF KNOWLEDGE OF A SIGNATURE
#[cfg(feature = "bbsplus_blind")]
macro_rules! blind_proof_tests {
    ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
        #[test] fn $n() { blind_proof_check::<$t>($p, $f); }
    )+)+ }
}

#[cfg(feature = "bbsplus_blind")]
blind_proof_tests! {
    (BbsBls12381Sha256, "./fixture_data/fixture_data_blind/bls12-381-sha-256/"): {
        (blind_proof_check_sha256_1, "proof/proof001.json"),
        (blind_proof_check_sha256_2, "proof/proof002.json"),
        (blind_proof_check_sha256_3, "proof/proof003.json"),
        (blind_proof_check_sha256_4, "proof/proof004.json"),
        (blind_proof_check_sha256_5, "proof/proof005.json"),
        (blind_proof_check_sha256_6, "proof/proof006.json"),
        (blind_proof_check_sha256_7, "proof/proof007.json"),
        (blind_proof_check_sha256_8, "proof/proof008.json"),
        (blind_proof_check_sha256_9, "proof/proof009.json"),
        (blind_proof_check_sha256_10, "proof/proof010.json"),
        (blind_proof_check_sha256_11, "proof/proof011.json"),
    },
    (BbsBls12381Shake256, "./fixture_data/fixture_data_blind/bls12-381-shake-256/"): {
        (blind_proof_check_shake256_1, "proof/proof001.json"),
        (blind_proof_check_shake256_2, "proof/proof002.json"),
        (blind_proof_check_shake256_3, "proof/proof003.json"),
        (blind_proof_check_shake256_4, "proof/proof004.json"),
        (blind_proof_check_shake256_5, "proof/proof005.json"),
        (blind_proof_check_shake256_6, "proof/proof006.json"),
        (blind_proof_check_shake256_7, "proof/proof007.json"),
        (blind_proof_check_shake256_8, "proof/proof008.json"),
        (blind_proof_check_shake256_9, "proof/proof009.json"),
        (blind_proof_check_shake256_10, "proof/proof010.json"),
        (blind_proof_check_shake256_11, "proof/proof011.json"),
    },
}

fn mocked_rng<S: Scheme>(pathname: &str, filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let data =
        std::fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
    let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    eprintln!("Mocked Random Scalars");

    let seed_ = hex::decode(res["seed"].as_str().unwrap()).unwrap();
    let dst = hex::decode(res["dst"].as_str().unwrap()).unwrap();
    let count: usize = res["count"].as_u64().unwrap().try_into().unwrap();

    let mocked_scalars_hex: Vec<&str> = res["mockedScalars"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();

    let r = seeded_random_scalars::<S::Ciphersuite>(count, &seed_, &dst);

    let mut results = true;

    for i in 0..count {
        let scalar_hex = hex::encode(r[i].to_bytes_be());

        let scalar_expected = mocked_scalars_hex[i];

        if scalar_hex != scalar_expected {
            if results {
                results = false
            }
            eprintln!(" count: {}", i);
            eprintln!(" Expected scalar: {}", scalar_expected);
            eprintln!(" Computed scalar: {}", scalar_hex);
        }
    }

    assert!(results, "Failed");
}

fn proof_check<S: Scheme>(pathname: &str, proof_filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let data = std::fs::read_to_string([pathname, proof_filename].concat())
        .expect("Unable to read file");
    let proof_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");

    let signerPK_hex = proof_json["signerPublicKey"].as_str().unwrap();
    let header_hex = proof_json["header"].as_str().unwrap();
    let ph_hex = proof_json["presentationHeader"].as_str().unwrap();
    let input_messages: Vec<String> = proof_json["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| serde_json::from_value(m.clone()).unwrap())
        .collect();

    let proof_expected = proof_json["proof"].as_str().unwrap();
    let result_expected = proof_json["result"]["valid"].as_bool().unwrap();

    let ph = hex::decode(ph_hex).unwrap();

    let revealed_message_indexes: Vec<usize> = proof_json["disclosedIndexes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| serde_json::from_value(m.clone()).unwrap())
        .collect();

    //Get Message Signature
    let signature_expected = proof_json["signature"].as_str().unwrap();

    let signature = Signature::<BBSplus<S::Ciphersuite>>::
    from_bytes(
        hex::decode(signature_expected)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap(),
    )
    .unwrap();

    let header = hex::decode(header_hex).unwrap();
    let PK = BBSplusPublicKey::from_bytes(&hex::decode(signerPK_hex).unwrap()).unwrap();

    let msgs: Vec<Vec<u8>> = input_messages
        .iter()
        .map(|m| hex::decode(m).unwrap())
        .collect();

    let proof = PoKSignature::<BBSplus<S::Ciphersuite>>::
    proof_gen(
        &PK,
        &signature.to_bytes(),
        Some(&header),
        Some(&ph),
        Some(&msgs),
        Some(&revealed_message_indexes),
    )
    .unwrap();
    let my_encoded_proof = hex::encode(proof.to_bytes());
    let result0 = proof_expected == my_encoded_proof;
    let result1 = result0 == result_expected;
    if !result1 {
        println!("  proofGen: {}", result1);
        println!("  Expected: {}", proof_expected);
        println!("  Computed: {}", my_encoded_proof);
        assert!(result1, "Failed");
    }

    // Verify the Proof
    let disclosed_messages = get_messages_vec(&msgs, &revealed_message_indexes);

    let PROOF = PoKSignature::<BBSplus<S::Ciphersuite>>::
    from_bytes(
        &hex::decode(proof_expected).unwrap(),
    )
    .unwrap();

    let result2 = PROOF
        .proof_verify(
            &PK,
            Some(&disclosed_messages),
            Some(&revealed_message_indexes),
            Some(&header),
            Some(&ph),
        )
        .is_ok();
    let result3 = result2 == result_expected;
    if !result3 {
        eprintln!("  proofVerify: {}", result3);
        eprintln!("  Expected: {}", result_expected);
        eprintln!("  Computed: {}", result2);
        assert!(result3, "failed");
    } else {
        eprintln!("  Expected: {}", signature_expected);
        eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));

        eprintln!("  proofVerify: {}", result3);
        eprintln!("  Expected: {}", result_expected);
        eprintln!("  Computed: {}", result2);
        if !result_expected {
            eprintln!(
                "{} ({})",
                result3,
                proof_json["result"]["reason"].as_str().unwrap()
            );
        }
    }
}

#[cfg(feature = "bbsplus_blind")]
fn blind_proof_check<S: Scheme>(pathname: &str, proof_filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let data = std::fs::read_to_string([pathname, proof_filename].concat())
        .expect("Unable to read file");
    let proof_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    println!("{}", proof_json["caseName"]);

    let signature_file = proof_json["signatureFile"].as_str().unwrap();
    let sig_data = std::fs::read_to_string([pathname, "signature/", signature_file].concat())
        .expect("Unable to read signature file");
    let sig_json: serde_json::Value =
        serde_json::from_str(&sig_data).expect("Unable to parse");

    let pk = BBSplusPublicKey::from_bytes(
        &hex::decode(proof_json["signerPublicKey"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let signature = BBSplusSignature::from_bytes(
        &hex::decode(sig_json["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();

    let issuer_messages = parse_messages(&sig_json["messages"]);
    let blind_messages = parse_messages(&sig_json["blindMessages"]);
    let secret_prover_blind = sig_json["proverBlind"].as_str().map(|b| {
        BlindFactor::from_bytes(&hex::decode(b).unwrap().try_into().unwrap()).unwrap()
    });

    let header = hex::decode(proof_json["header"].as_str().unwrap()).unwrap();
    let ph = hex::decode(proof_json["presentationHeader"].as_str().unwrap()).unwrap();

    let issuer_disclosures = parse_disclosures(&proof_json["messageDisclosures"]);
    let blind_disclosures = parse_disclosures(&proof_json["blindMessageDisclosures"]);
    let L = proof_json["L"].as_u64().unwrap() as usize;
    assert_eq!(L, issuer_messages.len());

    let expected_count = proof_json["mockRngParameters"]["proof"]["count"]
        .as_u64()
        .unwrap() as usize;
    let N = issuer_disclosures
        .iter()
        .chain(&blind_disclosures)
        .filter(|d| **d == Disclosure::Commit)
        .count();
    let R = issuer_disclosures
        .iter()
        .chain(&blind_disclosures)
        .filter(|d| **d == Disclosure::Disclose)
        .count();
    let U = issuer_messages.len() + 1 + blind_messages.len() - R;
    assert_eq!(5 + U + 2 * N, expected_count, "random scalars count");

    let (proof, add_zkp_info) = BlindPoKSignature::<BBSplus<S::Ciphersuite>>::blind_proof_gen(
        &pk,
        &signature.to_bytes(),
        BlindProofGenInput {
            header: Some(&header),
            ph: Some(&ph),
            issuer_messages: &issuer_messages,
            blind_messages: &blind_messages,
            issuer_message_disclosures: &issuer_disclosures,
            blind_message_disclosures: &blind_disclosures,
            secret_prover_blind: secret_prover_blind.as_ref(),
        },
    )
    .unwrap();

    let trace = &proof_json["trace"];
    let C_i = proof
        .to_bbsplus_blind_proof()
        .commitments()
        .iter()
        .map(|c| hex::encode(c.to_affine().to_compressed()))
        .collect::<Vec<_>>();
    let expected_C_i = trace["C_i"]
        .as_array()
        .map(|a| a.iter().map(|c| c.as_str().unwrap().to_owned()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert_eq!(C_i, expected_C_i, "commitments C_i");

    let s_i = add_zkp_info
        .commitment_rands
        .iter()
        .map(|s| hex::encode(s.to_bytes_be()))
        .collect::<Vec<_>>();
    let expected_s_i = trace["randomScalars"]["s_i"]
        .as_array()
        .map(|a| a.iter().map(|c| c.as_str().unwrap().to_owned()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert_eq!(s_i, expected_s_i, "commitment rands s_i");
    assert_eq!(add_zkp_info.committed_message_scalars.len(), N);

    // the openings in add_zkp_info must reproduce exactly the commitments in the proof
    let recomputed =
        BlindPoKSignature::<BBSplus<S::Ciphersuite>>::recompute_commitments(&add_zkp_info)
            .unwrap();
    assert_eq!(recomputed, proof.to_bbsplus_blind_proof().commitments());

    if let Some(challenge) = trace["challenge"].as_str() {
        assert_eq!(
            hex::encode(proof.to_bbsplus_blind_proof().bbs_proof.challenge.to_bytes_be()),
            challenge,
            "challenge"
        );
    }

    let expected_proof = proof_json["proof"].as_str().unwrap();
    let proof_bytes = proof.to_bytes();
    assert_eq!(hex::encode(&proof_bytes), expected_proof);

    // octets_to_proof round trip
    let parsed =
        BlindPoKSignature::<BBSplus<S::Ciphersuite>>::from_bytes(&proof_bytes, N).unwrap();
    assert_eq!(parsed.to_bbsplus_blind_proof(), proof.to_bbsplus_blind_proof());

    // Verifier side: disclosed issuer messages followed by disclosed blind messages
    let disclosed_messages = issuer_messages
        .iter()
        .zip(&issuer_disclosures)
        .chain(blind_messages.iter().zip(&blind_disclosures))
        .filter(|(_, d)| **d == Disclosure::Disclose)
        .map(|(m, _)| m.clone())
        .collect::<Vec<_>>();
    let message_disclosures = issuer_disclosures
        .iter()
        .chain(&blind_disclosures)
        .copied()
        .collect::<Vec<_>>();

    let result = parsed
        .blind_proof_verify(
            &pk,
            BlindProofVerifyInput {
                header: Some(&header),
                ph: Some(&ph),
                issuer_known_messages_no: L,
                disclosed_messages: &disclosed_messages,
                message_disclosures: &message_disclosures,
            },
        )
        .is_ok();

    let expected_result = proof_json["result"]["valid"].as_bool().unwrap();
    assert_eq!(result, expected_result);
}

// ---------------------------------------------------------------------------------------
// Negative tests for BlindProofGen / BlindProofVerify / octets_to_proof (draft 05).
// They start from the valid fixture proof009 (2 issuer COMMIT + blind DISCLOSE/HIDE) and
// alter one input at a time.
// ---------------------------------------------------------------------------------------

#[cfg(feature = "bbsplus_blind")]
struct BlindProofCase {
    pk: BBSplusPublicKey,
    signature: Vec<u8>,
    header: Vec<u8>,
    ph: Vec<u8>,
    issuer_messages: Vec<Message>,
    blind_messages: Vec<Message>,
    issuer_disclosures: Vec<Disclosure>,
    blind_disclosures: Vec<Disclosure>,
    secret_prover_blind: Option<BlindFactor>,
    proof: BlindPoKSignature<BBSplus<<BbsBls12381Sha256 as Scheme>::Ciphersuite>>,
    add_zkp_info: AddZkpInfo,
}

#[cfg(feature = "bbsplus_blind")]
type BlindSha256 = BlindPoKSignature<BBSplus<<BbsBls12381Sha256 as Scheme>::Ciphersuite>>;

#[cfg(feature = "bbsplus_blind")]
impl BlindProofCase {
    fn load() -> Self {
        let pathname = "./fixture_data/fixture_data_blind/bls12-381-sha-256/";
        let proof_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string([pathname, "proof/proof009.json"].concat()).unwrap(),
        )
        .unwrap();
        let sig_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                [pathname, "signature/", proof_json["signatureFile"].as_str().unwrap()]
                    .concat(),
            )
            .unwrap(),
        )
        .unwrap();

        let pk = BBSplusPublicKey::from_bytes(
            &hex::decode(proof_json["signerPublicKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let signature = hex::decode(sig_json["signature"].as_str().unwrap()).unwrap();
        let issuer_messages = parse_messages(&sig_json["messages"]);
        let blind_messages = parse_messages(&sig_json["blindMessages"]);
        let secret_prover_blind = sig_json["proverBlind"].as_str().map(|b| {
            BlindFactor::from_bytes(&hex::decode(b).unwrap().try_into().unwrap()).unwrap()
        });
        let header = hex::decode(proof_json["header"].as_str().unwrap()).unwrap();
        let ph = hex::decode(proof_json["presentationHeader"].as_str().unwrap()).unwrap();
        let issuer_disclosures = parse_disclosures(&proof_json["messageDisclosures"]);
        let blind_disclosures = parse_disclosures(&proof_json["blindMessageDisclosures"]);

        let (proof, add_zkp_info) = BlindSha256::blind_proof_gen(
            &pk,
            &signature,
            BlindProofGenInput {
                header: Some(&header),
                ph: Some(&ph),
                issuer_messages: &issuer_messages,
                blind_messages: &blind_messages,
                issuer_message_disclosures: &issuer_disclosures,
                blind_message_disclosures: &blind_disclosures,
                secret_prover_blind: secret_prover_blind.as_ref(),
            },
        )
        .unwrap();

        Self {
            pk,
            signature,
            header,
            ph,
            issuer_messages,
            blind_messages,
            issuer_disclosures,
            blind_disclosures,
            secret_prover_blind,
            proof,
            add_zkp_info,
        }
    }

    fn message_disclosures(&self) -> Vec<Disclosure> {
        self.issuer_disclosures
            .iter()
            .chain(&self.blind_disclosures)
            .copied()
            .collect()
    }

    fn disclosed_messages(&self) -> Vec<Message> {
        self.issuer_messages
            .iter()
            .chain(&self.blind_messages)
            .zip(self.message_disclosures())
            .filter(|(_, d)| *d == Disclosure::Disclose)
            .map(|(m, _)| m.clone())
            .collect()
    }

    fn commitments_count(&self) -> usize {
        self.add_zkp_info.commitment_rands.len()
    }

    fn gen(
        &self,
        issuer_disclosures: &[Disclosure],
        blind_disclosures: &[Disclosure],
    ) -> Result<(BlindSha256, AddZkpInfo), Error> {
        BlindSha256::blind_proof_gen(
            &self.pk,
            &self.signature,
            BlindProofGenInput {
                header: Some(&self.header),
                ph: Some(&self.ph),
                issuer_messages: &self.issuer_messages,
                blind_messages: &self.blind_messages,
                issuer_message_disclosures: issuer_disclosures,
                blind_message_disclosures: blind_disclosures,
                secret_prover_blind: self.secret_prover_blind.as_ref(),
            },
        )
    }

    fn verify_with(
        &self,
        proof: &BlindSha256,
        ph: &[u8],
        L: usize,
        disclosed_messages: &[Message],
        message_disclosures: &[Disclosure],
    ) -> Result<(), Error> {
        proof.blind_proof_verify(
            &self.pk,
            BlindProofVerifyInput {
                header: Some(&self.header),
                ph: Some(ph),
                issuer_known_messages_no: L,
                disclosed_messages,
                message_disclosures,
            },
        )
    }

    fn verify(&self, proof: &BlindSha256) -> Result<(), Error> {
        self.verify_with(
            proof,
            &self.ph,
            self.issuer_messages.len(),
            &self.disclosed_messages(),
            &self.message_disclosures(),
        )
    }

    /// proof with the inner fields replaced by `f`
    fn tampered(&self, f: impl FnOnce(&mut BBSplusBlindPoKSignature)) -> BlindSha256 {
        let mut inner = self.proof.to_bbsplus_blind_proof().clone();
        f(&mut inner);
        BlindPoKSignature::BBSplus(inner)
    }
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn blind_proof_case_is_valid() {
    // sanity check: the unaltered case must verify, so the failures below are meaningful
    let case = BlindProofCase::load();
    assert_eq!(case.commitments_count(), 2);
    case.verify(&case.proof).unwrap();
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn blind_proof_gen_rejects_wrong_disclosures_length() {
    let case = BlindProofCase::load();
    let mut short_issuer = case.issuer_disclosures.clone();
    short_issuer.pop();
    assert!(case.gen(&short_issuer, &case.blind_disclosures).is_err());

    let mut long_blind = case.blind_disclosures.clone();
    long_blind.push(Disclosure::Hide);
    assert!(case.gen(&case.issuer_disclosures, &long_blind).is_err());

    // disclosures omitted while messages are present: defaults to [] -> length mismatch
    assert!(BlindSha256::blind_proof_gen(
        &case.pk,
        &case.signature,
        BlindProofGenInput {
            header: Some(&case.header),
            ph: Some(&case.ph),
            issuer_messages: &case.issuer_messages,
            blind_messages: &case.blind_messages,
            secret_prover_blind: case.secret_prover_blind.as_ref(),
            ..Default::default()
        },
    )
    .is_err());
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn core_blind_proof_gen_rejects_invalid_indexes() {
    type CS = <BbsBls12381Sha256 as Scheme>::Ciphersuite;
    let case = BlindProofCase::load();
    let api_id = CS::API_ID_BLIND;
    let L = case.issuer_messages.len();
    let M = case.blind_messages.len();
    let generators = Generators::create::<CS>(L + 1, Some(api_id))
        .append(Generators::create::<CS>(M + 1, Some(&[b"BLIND_", api_id].concat())));
    let messages: Vec<BBSplusMessage> = (0..L + 1 + M)
        .map(|i| BBSplusMessage::new(Scalar::from(i as u64 + 1)))
        .collect();
    let signature = BBSplusSignature::from_bytes(
        &case.signature.clone().try_into().unwrap(),
    )
    .unwrap();

    let gen = |disclosed: &[usize], committed: &[usize]| {
        core_blind_proof_gen::<CS>(
            &case.pk,
            &signature,
            &generators,
            None,
            None,
            &messages,
            disclosed,
            committed,
            Some(api_id),
            CS::SEED_MOCKED_SCALAR,
            CS::BLIND_PROOF_DST,
        )
    };

    // the same index both disclosed and committed
    assert!(gen(&[0, 2], &[2]).is_err());
    // not strictly ascending
    assert!(gen(&[], &[3, 1]).is_err());
    assert!(gen(&[4, 4], &[]).is_err());
    // out of range
    assert!(gen(&[], &[L + 1 + M]).is_err());
    assert!(gen(&[L + 1 + M], &[]).is_err());
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn blind_proof_from_bytes_rejects_wrong_commitments_count() {
    let case = BlindProofCase::load();
    let bytes = case.proof.to_bytes();
    let N = case.commitments_count();
    assert!(BlindSha256::from_bytes(&bytes, N).is_ok());
    assert!(BlindSha256::from_bytes(&bytes, N - 1).is_err());
    assert!(BlindSha256::from_bytes(&bytes, N + 1).is_err());
    assert!(BlindSha256::from_bytes(&bytes, usize::MAX).is_err());
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn blind_proof_from_bytes_rejects_malformed_input() {
    let case = BlindProofCase::load();
    let bytes = case.proof.to_bytes();
    let N = case.commitments_count();

    // shorter than the 8-byte length prefix
    assert!(BlindSha256::from_bytes(&bytes[..7], N).is_err());
    // truncated / extended
    assert!(BlindSha256::from_bytes(&bytes[..bytes.len() - 1], N).is_err());
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(BlindSha256::from_bytes(&extended, N).is_err());

    // bbs_proof_len pointing past the end of the buffer
    let mut huge_len = bytes.clone();
    huge_len[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    assert!(BlindSha256::from_bytes(&huge_len, N).is_err());

    let bbs_len = u64::from_be_bytes(bytes[..8].try_into().unwrap()) as usize;
    let C_start = 8 + bbs_len;
    let s_start = C_start + N * G1Projective::COMPRESSED_BYTES;

    // C_1 = Identity_G1
    let mut identity_C = bytes.clone();
    identity_C[C_start..C_start + G1Projective::COMPRESSED_BYTES]
        .copy_from_slice(&G1Projective::IDENTITY.to_affine().to_compressed());
    assert!(BlindSha256::from_bytes(&identity_C, N).is_err());

    // C_1 not a valid point encoding
    let mut invalid_C = bytes.clone();
    invalid_C[C_start..C_start + G1Projective::COMPRESSED_BYTES].fill(0xff);
    assert!(BlindSha256::from_bytes(&invalid_C, N).is_err());

    // s^_1 = 0
    let mut zero_s = bytes.clone();
    zero_s[s_start..s_start + Scalar::BYTES].fill(0);
    assert!(BlindSha256::from_bytes(&zero_s, N).is_err());

    // s^_1 >= r
    let mut big_s = bytes.clone();
    big_s[s_start..s_start + Scalar::BYTES].fill(0xff);
    assert!(BlindSha256::from_bytes(&big_s, N).is_err());
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn blind_proof_verify_rejects_tampered_commitment() {
    let case = BlindProofCase::load();
    let proof = case.tampered(|p| p.commitments[0] = G1Projective::GENERATOR);
    assert!(case.verify(&proof).is_err());

    // swapping the two commitments must also fail: each C_i is bound to its index
    let proof = case.tampered(|p| p.commitments.swap(0, 1));
    assert!(case.verify(&proof).is_err());
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn blind_proof_verify_rejects_tampered_commitment_proof() {
    let case = BlindProofCase::load();
    let proof = case.tampered(|p| p.commitments_proof[1] += Scalar::ONE);
    assert!(case.verify(&proof).is_err());
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn blind_proof_verify_rejects_wrong_issuer_known_messages_no() {
    let case = BlindProofCase::load();
    let L = case.issuer_messages.len();
    let disclosed = case.disclosed_messages();
    let disclosures = case.message_disclosures();
    assert!(case.verify_with(&case.proof, &case.ph, L - 1, &disclosed, &disclosures).is_err());
    assert!(case.verify_with(&case.proof, &case.ph, L + 1, &disclosed, &disclosures).is_err());
    // larger than the total number of messages
    assert!(case
        .verify_with(&case.proof, &case.ph, L + 100, &disclosed, &disclosures)
        .is_err());
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn blind_proof_verify_rejects_wrong_message_disclosures() {
    let case = BlindProofCase::load();
    let L = case.issuer_messages.len();
    let disclosed = case.disclosed_messages();
    let disclosures = case.message_disclosures();

    // a COMMIT turned into HIDE: the commitment count no longer matches the proof
    let mut commit_to_hide = disclosures.clone();
    let i = commit_to_hide.iter().position(|d| *d == Disclosure::Commit).unwrap();
    commit_to_hide[i] = Disclosure::Hide;
    assert!(case.verify_with(&case.proof, &case.ph, L, &disclosed, &commit_to_hide).is_err());

    // a COMMIT moved to another hidden index: same count, wrong binding
    let mut moved = disclosures.clone();
    let j = moved.iter().position(|d| *d == Disclosure::Hide).unwrap();
    moved.swap(i, j);
    assert!(case.verify_with(&case.proof, &case.ph, L, &disclosed, &moved).is_err());

    // wrong length
    let mut short = disclosures.clone();
    short.pop();
    assert!(case.verify_with(&case.proof, &case.ph, L, &disclosed, &short).is_err());
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn blind_proof_verify_rejects_wrong_disclosed_messages_or_ph() {
    let case = BlindProofCase::load();
    let L = case.issuer_messages.len();
    let disclosures = case.message_disclosures();

    let mut wrong_msg = case.disclosed_messages();
    wrong_msg[0] = Message::hash(b"not the signed message".to_vec());
    assert!(case.verify_with(&case.proof, &case.ph, L, &wrong_msg, &disclosures).is_err());

    let mut missing_msg = case.disclosed_messages();
    missing_msg.pop();
    assert!(case.verify_with(&case.proof, &case.ph, L, &missing_msg, &disclosures).is_err());

    let disclosed = case.disclosed_messages();
    assert!(case.verify_with(&case.proof, b"another ph", L, &disclosed, &disclosures).is_err());
}

#[cfg(feature = "bbsplus_blind")]
#[test]
fn recompute_commitments_rejects_inconsistent_add_zkp_info() {
    let case = BlindProofCase::load();
    let mut info = case.add_zkp_info.clone();
    info.commitment_rands.pop();
    assert!(BlindSha256::recompute_commitments(&info).is_err());

    // a different opening gives a different commitment
    let mut info = case.add_zkp_info.clone();
    info.committed_message_scalars[0] += Scalar::ONE;
    let recomputed = BlindSha256::recompute_commitments(&info).unwrap();
    assert_ne!(recomputed[0], case.proof.to_bbsplus_blind_proof().commitments()[0]);
    assert_eq!(recomputed[1], case.proof.to_bbsplus_blind_proof().commitments()[1]);
}
