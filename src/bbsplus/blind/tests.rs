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
        ciphersuites::BbsCiphersuite,
        commitment::{BlindFactor, Message},
        keys::{BBSplusPublicKey, BBSplusSecretKey},
        test_utils::{hex_value, parse_messages, read_fixture},
    },
    schemes::{
        algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
        generics::BlindSignature,
    },
};
use bls12_381_plus::Scalar;

/// A blind signature test vector (`signature/signatureXXX.json`).
struct SignCase {
    sk: BBSplusSecretKey,
    pk: BBSplusPublicKey,
    header: Vec<u8>,
    messages: Vec<Message>,
    blind_messages: Vec<Message>,
    commitment_with_proof: Option<Vec<u8>>,
    prover_blind: Option<BlindFactor>,
    signature: Vec<u8>,
    valid: bool,
}

impl SignCase {
    fn load(path: &str) -> Self {
        let json = read_fixture(path);
        println!("{}", json["caseName"]);
        Self {
            sk: BBSplusSecretKey::from_bytes(&hex_value(&json["signerKeyPair"]["secretKey"])).unwrap(),
            pk: BBSplusPublicKey::from_bytes(&hex_value(&json["signerKeyPair"]["publicKey"])).unwrap(),
            header: hex_value(&json["header"]),
            messages: parse_messages(&json["messages"]),
            blind_messages: parse_messages(&json["blindMessages"]),
            commitment_with_proof: json["commitmentWithProof"].as_str().map(|_| hex_value(&json["commitmentWithProof"])),
            prover_blind: json["proverBlind"].as_str().map(|_| {
                BlindFactor::from_bytes(&hex_value(&json["proverBlind"]).try_into().unwrap()).unwrap()
            }),
            signature: hex_value(&json["signature"]),
            valid: json["result"]["valid"].as_bool().unwrap(),
        }
    }

    fn sign<S: Scheme>(&self, commitment_with_proof: Option<&[u8]>) -> Result<BlindSignature<BBSplus<S::Ciphersuite>>, crate::errors::Error>
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(
            &self.sk,
            &self.pk,
            commitment_with_proof,
            Some(&self.header),
            Some(&self.messages),
        )
    }

    fn signature<S: Scheme>(&self) -> BlindSignature<BBSplus<S::Ciphersuite>>
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        BlindSignature::<BBSplus<S::Ciphersuite>>::from_bytes(&self.signature.clone().try_into().unwrap()).unwrap()
    }
}

macro_rules! sign_tests {
    ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
        #[test] fn $n() { blind_sign::<$t>($p, $f); }
    )+)+ }
}

sign_tests! {
    (BbsBls12381Sha256, "./fixture_data/fixture_data_blind/bls12-381-sha-256/"): {
        (blind_sign_sha256_1, "signature/signature001.json"),
        (blind_sign_sha256_2, "signature/signature002.json"),
        (blind_sign_sha256_3, "signature/signature003.json"),
        (blind_sign_sha256_4, "signature/signature004.json"),
        (blind_sign_sha256_5, "signature/signature005.json"),
    },
    (BbsBls12381Shake256, "./fixture_data/fixture_data_blind/bls12-381-shake-256/"): {
        (blind_sign_shake256_1, "signature/signature001.json"),
        (blind_sign_shake256_2, "signature/signature002.json"),
        (blind_sign_shake256_3, "signature/signature003.json"),
        (blind_sign_shake256_4, "signature/signature004.json"),
        (blind_sign_shake256_5, "signature/signature005.json"),
    },
}

fn blind_sign<S: Scheme>(pathname: &str, filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let case = SignCase::load(&[pathname, filename].concat());

    let signature = case.sign::<S>(case.commitment_with_proof.as_deref()).unwrap();
    assert_eq!(hex::encode(signature.to_bytes()), hex::encode(&case.signature));

    let result = signature
        .verify_blind_sign(
            &case.pk,
            Some(&case.header),
            Some(&case.messages),
            Some(&case.blind_messages),
            case.prover_blind.as_ref(),
        )
        .is_ok();
    assert_eq!(result, case.valid);
}

// NEGATIVE TESTS (BLIND-08)

const SHA256_SIGNATURES: &str = "./fixture_data/fixture_data_blind/bls12-381-sha-256/signature/";
const SHAKE256_SIGNATURES: &str = "./fixture_data/fixture_data_blind/bls12-381-shake-256/signature/";

fn check_rejects_malformed_commitment<S: Scheme>(dir: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    // Multiple blind and signer messages, with a commitment.
    let case = SignCase::load(&[dir, "signature004.json"].concat());
    let commitment = case.commitment_with_proof.clone().unwrap();
    assert!(case.sign::<S>(Some(&commitment)).is_ok());

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("point only", commitment[..48].to_vec()),
        ("a single scalar", commitment[..48 + 32].to_vec()),
        ("truncated", commitment[..commitment.len() - 1].to_vec()),
    ];
    let mut trailing = commitment.clone();
    trailing.push(0);
    cases.push(("trailing byte", trailing));
    let mut zero_scalar = commitment.clone();
    zero_scalar.extend([0u8; 32]);
    cases.push(("extra zero scalar", zero_scalar));
    let mut extra_m = commitment.clone();
    extra_m.extend(&commitment[48..80]);
    cases.push(("one m^ too many", extra_m));
    let mut tampered = commitment.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    cases.push(("tampered challenge", tampered));

    for (name, c) in cases {
        assert!(case.sign::<S>(Some(&c)).is_err(), "commitment '{name}' should be rejected");
    }
}

#[test]
fn blind_sign_rejects_malformed_commitment() {
    check_rejects_malformed_commitment::<BbsBls12381Sha256>(SHA256_SIGNATURES);
    check_rejects_malformed_commitment::<BbsBls12381Shake256>(SHAKE256_SIGNATURES);
}

fn flip_flag(m: &Message) -> Message {
    match m {
        Message::Hash(v) => Message::Raw(v.clone()),
        Message::Raw(v) => Message::Hash(v.clone()),
    }
}

fn check_verify_rejects_wrong_inputs<S: Scheme>(dir: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let case = SignCase::load(&[dir, "signature004.json"].concat());
    let signature = case.signature::<S>();
    let prover_blind = case.prover_blind.as_ref().unwrap();

    let verify = |header: &[u8], messages: &[Message], blind_messages: &[Message], blind: Option<&BlindFactor>| {
        signature
            .verify_blind_sign(&case.pk, Some(header), Some(messages), Some(blind_messages), blind)
            .is_ok()
    };

    assert!(verify(&case.header, &case.messages, &case.blind_messages, Some(prover_blind)));

    // secret_prover_blind
    let wrong_blind = BlindFactor(prover_blind.0 + Scalar::ONE);
    assert!(!verify(&case.header, &case.messages, &case.blind_messages, Some(&wrong_blind)), "wrong prover blind");
    assert!(!verify(&case.header, &case.messages, &case.blind_messages, None), "missing prover blind");

    // header
    let mut header = case.header.clone();
    header.push(0);
    assert!(!verify(&header, &case.messages, &case.blind_messages, Some(prover_blind)), "different header");
    assert!(!verify(&[], &case.messages, &case.blind_messages, Some(prover_blind)), "empty header");

    // issuer / blind split
    assert!(!verify(&case.header, &case.blind_messages, &case.messages, Some(prover_blind)), "swapped lists");
    let mut fewer = case.messages.clone();
    let mut more = vec![fewer.pop().unwrap()];
    more.extend(case.blind_messages.iter().cloned());
    assert!(!verify(&case.header, &fewer, &more, Some(prover_blind)), "issuer message moved to the blind list");
    let all: Vec<Message> = case.messages.iter().chain(&case.blind_messages).cloned().collect();
    assert!(!verify(&case.header, &all, &[], Some(prover_blind)), "all messages as issuer messages");

    // single message changed or with the other flag
    for i in 0..case.messages.len() {
        let mut messages = case.messages.clone();
        messages[i] = Message::Hash(b"tampered".to_vec());
        assert!(!verify(&case.header, &messages, &case.blind_messages, Some(prover_blind)), "issuer message {i} changed");
        messages[i] = flip_flag(&case.messages[i]);
        assert!(!verify(&case.header, &messages, &case.blind_messages, Some(prover_blind)), "issuer message {i} flag");
    }
    for i in 0..case.blind_messages.len() {
        let mut blind_messages = case.blind_messages.clone();
        blind_messages[i] = Message::Hash(b"tampered".to_vec());
        assert!(!verify(&case.header, &case.messages, &blind_messages, Some(prover_blind)), "blind message {i} changed");
        blind_messages[i] = flip_flag(&case.blind_messages[i]);
        assert!(!verify(&case.header, &case.messages, &blind_messages, Some(prover_blind)), "blind message {i} flag");
    }

    // a signature without commitment must not verify with a blind factor or blind messages
    let no_commit = SignCase::load(&[dir, "signature005.json"].concat());
    let signature = no_commit.signature::<S>();
    let verify = |blind_messages: &[Message], blind: Option<&BlindFactor>| {
        signature
            .verify_blind_sign(&no_commit.pk, Some(&no_commit.header), Some(&no_commit.messages), Some(blind_messages), blind)
            .is_ok()
    };
    assert!(verify(&[], None));
    assert!(!verify(&[], Some(prover_blind)), "unexpected prover blind");
    assert!(!verify(&case.blind_messages, None), "unexpected blind messages");
}

#[test]
fn verify_blind_sign_rejects_wrong_inputs() {
    check_verify_rejects_wrong_inputs::<BbsBls12381Sha256>(SHA256_SIGNATURES);
    check_verify_rejects_wrong_inputs::<BbsBls12381Shake256>(SHAKE256_SIGNATURES);
}
