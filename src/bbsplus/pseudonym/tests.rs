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

use serde_json::Value;
use bls12_381_plus::{group::Curve, G1Projective, Scalar};
use crate::{
    bbsplus::{ciphersuites::BbsCiphersuite, commitment::{BlindFactor, Message}, generators::Generators,
              keys::{BBSplusPublicKey, BBSplusSecretKey},
    proof::{AddZkpInfo, BBSplusBlindPoKSignature, BlindProofGenInput, BlindProofVerifyInput, Disclosure},
    pseudonym::{core_proof_gen_with_nym, PseudonymSecret, VerifyFinalizeWithNymInput}, signature::BBSplusSignature,
    test_utils::{hex_value, parse_disclosures, read_fixture}},
    schemes::{
        algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
        generics::{BlindPoKSignature, BlindSignature, Commitment},
    },
    utils::{message::bbsplus_message::BBSplusMessage, util::bbsplus_utils::ScalarExt},
};

// FROM_BYTES LENGTH VALIDATION

use crate::{bbsplus::{pseudonym::BBSplusPseudonym, test_utils::{parse_messages, valid_fixture_bytes}}, errors::Error};

const NYM_FIXTURE_DIRS: [&str; 2] = [
    "./fixture_data/fixture_data_nym/bls12-381-sha-256/nymProof/",
    "./fixture_data/fixture_data_nym/bls12-381-shake-256/nymProof/",
];

fn assert_pseudonym_rejected(bytes: &[u8]) {
    assert!(
        matches!(BBSplusPseudonym::from_bytes(bytes), Err(Error::InvalidPseudonym)),
        "pseudonym of {} bytes should be rejected",
        bytes.len()
    );
}

#[test]
fn pseudonym_secret_is_zeroized() {
    use zeroize::{Zeroize, ZeroizeOnDrop};
    fn zeroize_on_drop<T: ZeroizeOnDrop>() {}
    zeroize_on_drop::<PseudonymSecret>();

    let mut secrets = PseudonymSecret::random_vec(3);
    secrets[0].zeroize();
    assert_eq!(secrets[0].0, Scalar::ZERO);
    secrets.zeroize();
    assert!(secrets.is_empty());
}

#[test]
fn pseudonym_from_bytes_round_trip() {
    for dir in NYM_FIXTURE_DIRS {
        for nym in valid_fixture_bytes(dir, "pseudonym") {
            assert_eq!(BBSplusPseudonym::from_bytes(&nym).unwrap().to_bytes(), nym);
        }
    }
}

#[test]
fn pseudonym_from_bytes_rejects_invalid_lengths() {
    // 48 zero bytes have the right length but are not a valid compressed G1 point.
    for len in [0usize, 1, 47, 48, 49, 96] {
        assert_pseudonym_rejected(&vec![0u8; len]);
    }
    for dir in NYM_FIXTURE_DIRS {
        for nym in valid_fixture_bytes(dir, "pseudonym") {
            assert_pseudonym_rejected(&nym[..47]);
            for extra in [1usize, 32] {
                let mut bytes = nym.clone();
                bytes.extend(std::iter::repeat_n(0u8, extra));
                assert_pseudonym_rejected(&bytes);
            }
        }
    }
}

macro_rules! commit_tests {
    ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
        #[test] fn $n() { commit_with_nym::<$t>($p, $f); }
    )+)+ }
}

commit_tests! {
    (BbsBls12381Sha256, "./fixture_data/fixture_data_nym/bls12-381-sha-256/"): {
        (commit_sha256_1, "nymCommit/nymCommit001.json"),
        (commit_sha256_2, "nymCommit/nymCommit002.json"),
        (commit_sha256_3, "nymCommit/nymCommit003.json"),
        (commit_sha256_4, "nymCommit/nymCommit004.json"),
    },
    (BbsBls12381Shake256, "./fixture_data/fixture_data_nym/bls12-381-shake-256/"): {
        (commit_shake256_1, "nymCommit/nymCommit001.json"),
        (commit_shake256_2, "nymCommit/nymCommit002.json"),
        (commit_shake256_3, "nymCommit/nymCommit003.json"),
        (commit_shake256_4, "nymCommit/nymCommit004.json"),
    },
}

#[test]
fn pseudonym_secret_from_hex_rejects_malformed_input() {
    let valid = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418";
    assert!(PseudonymSecret::from_hex(valid).is_ok());
    let order_r = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";
    for bad in [
        "",
        &valid[1..],                // 63 chars: used to panic
        &valid[2..],                // 31 bytes
        &format!("{valid}00"),      // trailing data: used to be ignored
        &format!("zz{}", &valid[2..]), // not hex: used to panic
        order_r,                    // not < r
    ] {
        assert!(matches!(PseudonymSecret::from_hex(bad), Err(Error::InvalidPseudonym)), "{bad}");
    }
}

// prover_nyms is REQUIRED and the Signer rejects length_nym_vector < 1 (draft 05 §8.2).
fn commit_with_nym_rejects_empty_nyms<S: Scheme>()
where
    S::Ciphersuite: BbsCiphersuite,
{
    let blind_messages = [crate::bbsplus::commitment::Message::hash(b"msg".to_vec())];
    for messages in [None, Some(&blind_messages[..])] {
        assert!(matches!(
            Commitment::<BBSplus<S::Ciphersuite>>::commit_with_nym(messages, Vec::new()),
            Err(Error::InvalidNymSecretsLength)
        ));
    }
}

#[test]
fn commit_with_nym_rejects_empty_nyms_sha256() {
    commit_with_nym_rejects_empty_nyms::<BbsBls12381Sha256>();
}

#[test]
fn commit_with_nym_rejects_empty_nyms_shake256() {
    commit_with_nym_rejects_empty_nyms::<BbsBls12381Shake256>();
}

fn commit_with_nym<S: Scheme>(pathname: &str, filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let proof_json = read_fixture(&[pathname, filename].concat());
    println!("{}", proof_json["caseName"]);

    let prover_blind = proof_json["proverBlind"].as_str().unwrap();
    let commitment_with_proof = proof_json["commitmentWithProof"].as_str().unwrap();

    let prover_nyms = get_pseudonymsecrets(&proof_json, "proverNyms");

    let prover_nyms_len = prover_nyms.len();

    let blind_messages = parse_messages(&proof_json["blindMessages"]);

    let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

    let (commitment_with_proof_result, secret) =
    Commitment::<BBSplus<S::Ciphersuite>>::commit_with_nym(
        Some(&blind_messages),
        prover_nyms
    ).unwrap();

    let commitment_with_proof_result_oct = commitment_with_proof_result.to_bytes();

    assert_eq!(
        hex::encode(&commitment_with_proof_result_oct),
        commitment_with_proof
    );

    assert_eq!(hex::encode(secret.to_bytes()), prover_blind);

    // §7.1.1 step 3: M + 1 generators, with M = blind messages + prover nyms.
    let blind_generators = Generators::create::<S::Ciphersuite>(
        blind_messages.len() + prover_nyms_len + 1,
        Some(&[b"BLIND_", <S::Ciphersuite as BbsCiphersuite>::API_ID_NYM].concat()),
    );

    let result = Commitment::<BBSplus<S::Ciphersuite>>::deserialize_and_validate_commit(
        Some(&commitment_with_proof_result_oct),
        &blind_generators,
        Some(<S::Ciphersuite as BbsCiphersuite>::API_ID_NYM),
    )
    .is_ok();

    assert_eq!(result, expected_result);
} 

macro_rules! sign_tests {
    ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
        #[test] fn $n() { blind_sign_with_nym::<$t>($p, $f); }
    )+)+ }
}

sign_tests! {
    (BbsBls12381Sha256, "./fixture_data/fixture_data_nym/bls12-381-sha-256/"): {
        (blind_sign_with_nym_sha256_1, "nymSignature/nymSignature001.json"),
        (blind_sign_with_nym_sha256_2, "nymSignature/nymSignature002.json"),
        (blind_sign_with_nym_sha256_3, "nymSignature/nymSignature003.json"),
        (blind_sign_with_nym_sha256_4, "nymSignature/nymSignature004.json"),
        (blind_sign_with_nym_sha256_5, "nymSignature/nymSignature005.json"),
        (blind_sign_with_nym_sha256_6, "nymSignature/nymSignature006.json"),
        (blind_sign_with_nym_sha256_7, "nymSignature/nymSignature007.json"),
    },
    (BbsBls12381Shake256, "./fixture_data/fixture_data_nym/bls12-381-shake-256/"): {
        (blind_sign_with_nym_shake256_1, "nymSignature/nymSignature001.json"),
        (blind_sign_with_nym_shake256_2, "nymSignature/nymSignature002.json"),
        (blind_sign_with_nym_shake256_3, "nymSignature/nymSignature003.json"),
        (blind_sign_with_nym_shake256_4, "nymSignature/nymSignature004.json"),
        (blind_sign_with_nym_shake256_5, "nymSignature/nymSignature005.json"),
        (blind_sign_with_nym_shake256_6, "nymSignature/nymSignature006.json"),
        (blind_sign_with_nym_shake256_7, "nymSignature/nymSignature007.json"),
    },
}

// NEGATIVE TESTS: BLIND SIGN / VERIFY FINALIZE WITH NYM

/// Fixture with 5 blind messages and 10 prover nyms: the commitment has M = 15 scalars.
const NYM_SIGN_NEGATIVE_FIXTURE: &str = "nymSignature/nymSignature006.json";

fn nym_sign_negative_cases<S: Scheme>(pathname: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let json = read_fixture(&[pathname, NYM_SIGN_NEGATIVE_FIXTURE].concat());

    let sk = BBSplusSecretKey::from_bytes(&hex_value(&json["signerKeyPair"]["secretKey"])).unwrap();
    let pk = BBSplusPublicKey::from_bytes(&hex_value(&json["signerKeyPair"]["publicKey"])).unwrap();
    let commitment = hex_value(&json["commitmentWithProof"]);
    let header = hex_value(&json["header"]);
    let messages = parse_messages(&json["messages"]);
    let blind_messages = parse_messages(&json["blindMessages"]);
    let entropy = pseudonym_secret(&json["signer_nym_entropy"]);
    let M = blind_messages.len() + get_pseudonymsecrets(&json, "proverNyms").len();

    let sign = |c: Option<&[u8]>, n: usize| BlindSignature::<BBSplus<S::Ciphersuite>>::
        blind_sign_with_nym(&sk, &pk, c, n, Some(&header), &entropy, Some(&messages));

    // 1 <= length_nym_vector <= M
    for n in [0, M + 1, usize::MAX] {
        assert!(matches!(sign(Some(&commitment), n), Err(Error::InvalidNymSecretsLength)), "n = {n}");
    }
    assert!(sign(Some(&commitment), 1).is_ok());
    assert!(sign(Some(&commitment), M).is_ok());

    // No commitment: there is no prover nym to add the entropy to.
    assert!(matches!(sign(None, 1), Err(Error::InvalidNymSecretsLength)));
    assert!(matches!(sign(Some(&[]), 1), Err(Error::InvalidNymSecretsLength)));

    // Malformed commitment: rejected by the parser, before creating the generators.
    assert!(sign(Some(&commitment[..commitment.len() - 1]), 10).is_err());
    assert!(sign(Some(&commitment[..48]), 1).is_err());

    // VerifyFinalizeWithNym: prover_nyms is REQUIRED.
    let signature = sign(Some(&commitment), 10).unwrap();
    assert!(matches!(
        signature.verify_finalize_with_nym(
            &pk,
            Vec::new(),
            VerifyFinalizeWithNymInput {
                header: Some(&header),
                messages: &messages,
                blind_messages: &blind_messages,
                signer_nym_entropy: Some(&entropy),
                ..Default::default()
            },
        ),
        Err(Error::InvalidNymSecretsLength)
    ));
}

#[test]
fn blind_sign_with_nym_negative_sha256() {
    nym_sign_negative_cases::<BbsBls12381Sha256>("./fixture_data/fixture_data_nym/bls12-381-sha-256/");
}

#[test]
fn blind_sign_with_nym_negative_shake256() {
    nym_sign_negative_cases::<BbsBls12381Shake256>("./fixture_data/fixture_data_nym/bls12-381-shake-256/");
}

fn blind_sign_with_nym<S: Scheme>(pathname: &str, filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let proof_json = read_fixture(&[pathname, filename].concat());
    println!("{}", proof_json["caseName"]);

    let sk = BBSplusSecretKey::from_bytes(&hex_value(&proof_json["signerKeyPair"]["secretKey"])).unwrap();
    let pk = BBSplusPublicKey::from_bytes(&hex_value(&proof_json["signerKeyPair"]["publicKey"])).unwrap();

    let prover_blind = get_blind_factor(&proof_json, "proverBlind");

    let commitment_with_proof = proof_json["commitmentWithProof"]
        .is_string()
        .then(|| hex_value(&proof_json["commitmentWithProof"]));

    let blind_messages = parse_messages(&proof_json["blindMessages"]);

    let header = hex_value(&proof_json["header"]);

    let messages = parse_messages(&proof_json["messages"]);

    let signer_nym_entropy = pseudonym_secret(&proof_json["signer_nym_entropy"]);

    let prover_nyms = get_pseudonymsecrets(&proof_json, "proverNyms");
    
    let signature = BlindSignature::<BBSplus<S::Ciphersuite>>::
    blind_sign_with_nym(
        &sk,
        &pk,
        commitment_with_proof.as_deref(),
        prover_nyms.len(),
        Some(&header),
        &signer_nym_entropy,
        Some(&messages),
    )
    .unwrap();

    let expected_signature = proof_json["signature"].as_str().unwrap();
    let signature_oct = signature.to_bytes();

    assert_eq!(hex::encode(signature_oct), expected_signature);

    let nym_secrets = signature
        .verify_finalize_with_nym(
            &pk,
            prover_nyms,
            VerifyFinalizeWithNymInput {
                header: Some(&header),
                messages: &messages,
                blind_messages: &blind_messages,
                signer_nym_entropy: Some(&signer_nym_entropy),
                secret_prover_blind: prover_blind.as_ref(),
            },
        ).unwrap();

    let expected_nym_secrets: Vec<PseudonymSecret> = proof_json["nym_secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(pseudonym_secret)
        .collect::<Vec<PseudonymSecret>>();

    assert_eq!(nym_secrets, expected_nym_secrets);
}

macro_rules! nym_proof_tests {
    ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
        #[test] fn $n() { nym_proof_check::<$t>($p, $f); }
    )+)+ }
}

nym_proof_tests! {
    (BbsBls12381Sha256, "./fixture_data/fixture_data_nym/bls12-381-sha-256/"): {
        (nym_proof_check_sha256_1, "nymProof/nymProof001.json"),
        (nym_proof_check_sha256_2, "nymProof/nymProof002.json"),
        (nym_proof_check_sha256_3, "nymProof/nymProof003.json"),
        (nym_proof_check_sha256_4, "nymProof/nymProof004.json"),
        (nym_proof_check_sha256_5, "nymProof/nymProof005.json"),
        (nym_proof_check_sha256_6, "nymProof/nymProof006.json"),
        (nym_proof_check_sha256_7, "nymProof/nymProof007.json"),
        (nym_proof_check_sha256_8, "nymProof/nymProof008.json"),
        (nym_proof_check_sha256_9, "nymProof/nymProof009.json"),
        (nym_proof_check_sha256_10, "nymProof/nymProof010.json"),
        (nym_proof_check_sha256_11, "nymProof/nymProof011.json"),
        (nym_proof_check_sha256_101, "nymProof/nymProof101.json"),
        (nym_proof_check_sha256_102, "nymProof/nymProof102.json"),
        (nym_proof_check_sha256_103, "nymProof/nymProof103.json"),
        (nym_proof_check_sha256_104, "nymProof/nymProof104.json"),
        (nym_proof_check_sha256_105, "nymProof/nymProof105.json"),
    },
    (BbsBls12381Shake256, "./fixture_data/fixture_data_nym/bls12-381-shake-256/"): {
        (nym_proof_check_shake256_1, "nymProof/nymProof001.json"),
        (nym_proof_check_shake256_2, "nymProof/nymProof002.json"),
        (nym_proof_check_shake256_3, "nymProof/nymProof003.json"),
        (nym_proof_check_shake256_4, "nymProof/nymProof004.json"),
        (nym_proof_check_shake256_5, "nymProof/nymProof005.json"),
        (nym_proof_check_shake256_6, "nymProof/nymProof006.json"),
        (nym_proof_check_shake256_7, "nymProof/nymProof007.json"),
        (nym_proof_check_shake256_8, "nymProof/nymProof008.json"),
        (nym_proof_check_shake256_9, "nymProof/nymProof009.json"),
        (nym_proof_check_shake256_10, "nymProof/nymProof010.json"),
        (nym_proof_check_shake256_11, "nymProof/nymProof011.json"),
        (nym_proof_check_shake256_101, "nymProof/nymProof101.json"),
        (nym_proof_check_shake256_102, "nymProof/nymProof102.json"),
        (nym_proof_check_shake256_103, "nymProof/nymProof103.json"),
        (nym_proof_check_shake256_104, "nymProof/nymProof104.json"),
        (nym_proof_check_shake256_105, "nymProof/nymProof105.json"),
    },
}

/// A nym proof test vector together with the inputs of the signature it refers to.
type NymProofGen<S> = (BlindPoKSignature<BBSplus<<S as Scheme>::Ciphersuite>>, BBSplusPseudonym, AddZkpInfo);

struct NymProofCase {
    pk: BBSplusPublicKey,
    signature: Vec<u8>,
    header: Vec<u8>,
    ph: Vec<u8>,
    context_id: Vec<u8>,
    nym_secrets: Vec<PseudonymSecret>,
    issuer_messages: Vec<Message>,
    blind_messages: Vec<Message>,
    issuer_disclosures: Vec<Disclosure>,
    blind_disclosures: Vec<Disclosure>,
    secret_prover_blind: Option<BlindFactor>,
    json: Value,
}

impl NymProofCase {
    fn load(pathname: &str, proof_filename: &str) -> Self {
        let json = read_fixture(&[pathname, proof_filename].concat());
        let sig = read_fixture(
            &[pathname, "nymSignature/", json["signatureFile"].as_str().unwrap()].concat(),
        );
        Self {
            pk: BBSplusPublicKey::from_bytes(&hex_value(&json["signerPublicKey"])).unwrap(),
            signature: hex_value(&sig["signature"]),
            header: hex_value(&json["header"]),
            ph: hex_value(&json["presentationHeader"]),
            context_id: hex_value(&json["context_id"]),
            nym_secrets: get_pseudonymsecrets(&sig, "nym_secrets"),
            issuer_messages: parse_messages(&sig["messages"]),
            blind_messages: parse_messages(&sig["blindMessages"]),
            issuer_disclosures: parse_disclosures(&json["messageDisclosures"]),
            blind_disclosures: parse_disclosures(&json["blindMessageDisclosures"]),
            secret_prover_blind: get_blind_factor(&sig, "proverBlind"),
            json,
        }
    }

    fn gen<S: Scheme>(&self) -> Result<NymProofGen<S>, Error>
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        BlindPoKSignature::<BBSplus<S::Ciphersuite>>::proof_gen_with_nym(
            &self.pk,
            &self.signature,
            &self.nym_secrets,
            &self.context_id,
            BlindProofGenInput {
                header: Some(&self.header),
                ph: Some(&self.ph),
                issuer_messages: &self.issuer_messages,
                blind_messages: &self.blind_messages,
                issuer_message_disclosures: &self.issuer_disclosures,
                blind_message_disclosures: &self.blind_disclosures,
                secret_prover_blind: self.secret_prover_blind.as_ref(),
            },
        )
    }

    fn message_disclosures(&self) -> Vec<Disclosure> {
        self.issuer_disclosures.iter().chain(&self.blind_disclosures).copied().collect()
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
        self.message_disclosures().iter().filter(|d| **d == Disclosure::Commit).count()
    }

    fn verify<S: Scheme>(
        &self,
        proof: &BlindPoKSignature<BBSplus<S::Ciphersuite>>,
        pseudonym: &BBSplusPseudonym,
    ) -> Result<(), Error>
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        proof.proof_verify_with_nym(
            &self.pk,
            pseudonym,
            &self.context_id,
            self.nym_secrets.len(),
            BlindProofVerifyInput {
                header: Some(&self.header),
                ph: Some(&self.ph),
                issuer_known_messages_no: self.issuer_messages.len(),
                disclosed_messages: &self.disclosed_messages(),
                message_disclosures: &self.message_disclosures(),
            },
        )
    }
}

fn nym_proof_check<S: Scheme>(pathname: &str, proof_filename: &str)
where
    S::Ciphersuite: BbsCiphersuite,
{
    let case = NymProofCase::load(pathname, proof_filename);
    let json = &case.json;
    println!("{}", json["caseName"]);

    assert_eq!(json["L"].as_u64().unwrap() as usize, case.issuer_messages.len());

    // 5 + U + 2N random scalars (§8.1 step 1)
    let N = case.commitments_count();
    let R = case.disclosed_messages().len();
    let U = case.issuer_messages.len() + 1 + case.blind_messages.len() + case.nym_secrets.len() - R;
    assert_eq!(
        5 + U + 2 * N,
        json["mockRngParameters"]["proof"]["count"].as_u64().unwrap() as usize,
        "random scalars count"
    );

    let (proof, pseudonym, add_zkp_info) = case.gen::<S>().unwrap();

    let trace = &json["trace"];
    let hex_list = |v: &Value| -> Vec<String> {
        v.as_array()
            .map(|a| a.iter().map(|c| c.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default()
    };
    let C_i: Vec<String> = proof
        .to_bbsplus_blind_proof()
        .commitments()
        .iter()
        .map(|c| hex::encode(c.to_affine().to_compressed()))
        .collect();
    assert_eq!(C_i, hex_list(&trace["C_i"]), "commitments C_i");

    let s_i: Vec<String> =
        add_zkp_info.commitment_rands.iter().map(|s| hex::encode(s.to_bytes_be())).collect();
    assert_eq!(s_i, hex_list(&trace["randomScalars"]["s_i"]), "commitment rands s_i");
    let committed: Vec<String> = add_zkp_info
        .committed_message_scalars
        .iter()
        .map(|s| hex::encode(s.to_bytes_be()))
        .collect();
    assert_eq!(
        committed,
        hex_list(&json["add_zkp_info"]["committed_message_scalars"]),
        "add_zkp_info committed_message_scalars"
    );

    assert_eq!(
        hex::encode(pseudonym.to_bytes()),
        json["pseudonym"].as_str().unwrap(),
        "pseudonym"
    );
    assert_eq!(
        hex::encode(proof.to_bbsplus_blind_proof().bbs_proof.challenge.to_bytes_be()),
        trace["challenge"].as_str().unwrap(),
        "challenge"
    );

    let proof_bytes = proof.to_bytes();
    assert_eq!(hex::encode(&proof_bytes), json["proof"].as_str().unwrap(), "proof");

    // octets_to_proof round trip, then verification from the parsed values
    let parsed =
        BlindPoKSignature::<BBSplus<S::Ciphersuite>>::from_bytes(&proof_bytes, N).unwrap();
    assert_eq!(parsed.to_bbsplus_blind_proof(), proof.to_bbsplus_blind_proof());
    let parsed_pseudonym = BBSplusPseudonym::from_bytes(&pseudonym.to_bytes()).unwrap();

    let result = case.verify::<S>(&parsed, &parsed_pseudonym).is_ok();
    assert_eq!(result, json["result"]["valid"].as_bool().unwrap());
}

// NEGATIVE TESTS: PROOF GEN / VERIFY WITH NYM
// Start from nymProof010 (issuer and blind messages disclosed, hidden and committed) and
// alter one input at a time.

const NYM_PROOF_DIR: &str = "./fixture_data/fixture_data_nym/bls12-381-sha-256/";
type NymSha256 = BlindPoKSignature<BBSplus<<BbsBls12381Sha256 as Scheme>::Ciphersuite>>;

fn nym_negative_case() -> (NymProofCase, NymSha256, BBSplusPseudonym) {
    let case = NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json");
    let (proof, pseudonym, _) = case.gen::<BbsBls12381Sha256>().unwrap();
    // sanity check: the unaltered case verifies, so the failures below are meaningful
    case.verify::<BbsBls12381Sha256>(&proof, &pseudonym).unwrap();
    (case, proof, pseudonym)
}

#[test]
fn proof_gen_with_nym_rejects_invalid_inputs() {
    let (case, _, _) = nym_negative_case();

    let mut c = NymProofCase { nym_secrets: vec![], ..NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json") };
    assert!(matches!(c.gen::<BbsBls12381Sha256>(), Err(Error::InvalidNymSecretsLength)));

    // wrong number of disclosures
    c = NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json");
    c.issuer_disclosures.pop();
    assert!(c.gen::<BbsBls12381Sha256>().is_err());
    c = NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json");
    c.blind_disclosures.push(Disclosure::Hide);
    assert!(c.gen::<BbsBls12381Sha256>().is_err());

    // a nym secret vector different from the signed one: the proof does not verify
    c = NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json");
    c.nym_secrets[0] = &c.nym_secrets[0] + &c.nym_secrets[0];
    let (proof, pseudonym, _) = c.gen::<BbsBls12381Sha256>().unwrap();
    assert!(case.verify::<BbsBls12381Sha256>(&proof, &pseudonym).is_err());
}

#[test]
fn core_proof_gen_with_nym_rejects_revealed_nym_secrets() {
    type CS = <BbsBls12381Sha256 as Scheme>::Ciphersuite;
    let (case, _, _) = nym_negative_case();
    let signature = BBSplusSignature::from_bytes(&case.signature.clone().try_into().unwrap()).unwrap();
    let L = case.issuer_messages.len() + 1 + case.blind_messages.len();
    let n = case.nym_secrets.len();
    let api_id = CS::API_ID_NYM;
    let generators = Generators::create::<CS>(case.issuer_messages.len() + 1, Some(api_id)).append(
        Generators::create::<CS>(case.blind_messages.len() + n + 1, Some(&[b"BLIND_", api_id].concat())),
    );
    let scalars: Vec<BBSplusMessage> =
        (0..L + n).map(|i| BBSplusMessage::new(Scalar::from(i as u64 + 1))).collect();
    let gen = |disclosed: &[usize], committed: &[usize], len: usize| {
        core_proof_gen_with_nym::<CS>(
            &case.pk, &signature, &generators, None, None, &case.context_id, &scalars,
            disclosed, committed, len, Some(api_id), CS::SEED_MOCKED_SCALAR, CS::BLIND_PROOF_DST,
        )
    };
    let last = L + n - 1;
    assert!(gen(&[], &[], n).is_ok());
    // the nym secret disclosed or committed
    assert!(gen(&[last], &[], n).is_err());
    assert!(gen(&[], &[last], n).is_err());
    // length_nym_secrets 0 or larger than the scalars
    assert!(matches!(gen(&[], &[], 0), Err(Error::InvalidNymSecretsLength)));
    assert!(matches!(gen(&[], &[], L + n + 1), Err(Error::InvalidNymSecretsLength)));
    // with length 2 the last issuer/blind scalar becomes a nym position
    assert!(gen(&[last - 1], &[], 2).is_err());
}

#[test]
fn proof_verify_with_nym_rejects_wrong_pseudonym_or_context() {
    let (case, proof, _) = nym_negative_case();

    // the pseudonym of another context, or another context for the same pseudonym
    let other = NymProofCase { context_id: b"another context".to_vec(), ..NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json") };
    let (other_proof, other_pseudonym, _) = other.gen::<BbsBls12381Sha256>().unwrap();
    assert!(case.verify::<BbsBls12381Sha256>(&proof, &other_pseudonym).is_err());
    assert!(case.verify::<BbsBls12381Sha256>(&other_proof, &other_pseudonym).is_err());
    other.verify::<BbsBls12381Sha256>(&other_proof, &other_pseudonym).unwrap();

    // pseudonym equal to the identity, built in-crate (from_bytes rejects it)
    let identity = BBSplusPseudonym { pseudonym: G1Projective::IDENTITY };
    assert!(matches!(
        case.verify::<BbsBls12381Sha256>(&proof, &identity),
        Err(Error::InvalidPseudonym)
    ));
}

#[test]
fn proof_verify_with_nym_rejects_wrong_length_nym_vector() {
    let (case, proof, pseudonym) = nym_negative_case();
    let U = proof.to_bbsplus_blind_proof().bbs_proof.m_cap.len();
    for n in [0, 2, U, U + 1, usize::MAX] {
        let res = proof.proof_verify_with_nym(
            &case.pk,
            &pseudonym,
            &case.context_id,
            n,
            BlindProofVerifyInput {
                header: Some(&case.header),
                ph: Some(&case.ph),
                issuer_known_messages_no: case.issuer_messages.len(),
                disclosed_messages: &case.disclosed_messages(),
                message_disclosures: &case.message_disclosures(),
            },
        );
        assert!(res.is_err(), "length_nym_vector = {n}");
    }
}

#[test]
fn proof_verify_with_nym_rejects_wrong_disclosures() {
    let (case, proof, pseudonym) = nym_negative_case();
    let verify = |L: usize, disclosed: &[Message], disclosures: &[Disclosure], ph: &[u8]| {
        proof.proof_verify_with_nym(
            &case.pk,
            &pseudonym,
            &case.context_id,
            case.nym_secrets.len(),
            BlindProofVerifyInput {
                header: Some(&case.header),
                ph: Some(ph),
                issuer_known_messages_no: L,
                disclosed_messages: disclosed,
                message_disclosures: disclosures,
            },
        )
    };
    let L = case.issuer_messages.len();
    let disclosed = case.disclosed_messages();
    let disclosures = case.message_disclosures();
    verify(L, &disclosed, &disclosures, &case.ph).unwrap();

    // issuer_known_messages_no
    assert!(verify(L - 1, &disclosed, &disclosures, &case.ph).is_err());
    assert!(verify(L + 1, &disclosed, &disclosures, &case.ph).is_err());
    assert!(verify(usize::MAX, &disclosed, &disclosures, &case.ph).is_err());

    // a COMMIT moved to another hidden index: same count, wrong binding
    let mut moved = disclosures.clone();
    let i = moved.iter().position(|d| *d == Disclosure::Commit).unwrap();
    let j = moved.iter().position(|d| *d == Disclosure::Hide).unwrap();
    moved.swap(i, j);
    assert!(verify(L, &disclosed, &moved, &case.ph).is_err());

    // wrong length
    let mut short = disclosures.clone();
    short.pop();
    assert!(verify(L, &disclosed, &short, &case.ph).is_err());

    // wrong disclosed message, missing message, other ph
    let mut wrong = disclosed.clone();
    wrong[0] = Message::hash(b"not the signed message".to_vec());
    assert!(verify(L, &wrong, &disclosures, &case.ph).is_err());
    let mut missing = disclosed.clone();
    missing.pop();
    assert!(verify(L, &missing, &disclosures, &case.ph).is_err());
    assert!(verify(L, &disclosed, &disclosures, b"another ph").is_err());
}

#[test]
fn proof_verify_with_nym_rejects_tampered_proof() {
    let (case, proof, pseudonym) = nym_negative_case();
    let tampered = |f: &dyn Fn(&mut BBSplusBlindPoKSignature)| {
        let mut inner = proof.to_bbsplus_blind_proof().clone();
        f(&mut inner);
        NymSha256::BBSplus(inner)
    };
    // commitments, their proof of correctness and the m^ of the nym secret
    for p in [
        tampered(&|p| p.commitments[0] = G1Projective::GENERATOR),
        tampered(&|p| p.commitments.swap(0, 1)),
        tampered(&|p| p.commitments_proof[0] += Scalar::ONE),
        tampered(&|p| *p.bbs_proof.m_cap.last_mut().unwrap() += Scalar::ONE),
    ] {
        assert!(case.verify::<BbsBls12381Sha256>(&p, &pseudonym).is_err());
    }
}

#[test]
fn pseudonym_from_bytes_rejects_identity_and_base_point() {
    let (_, _, pseudonym) = nym_negative_case();
    assert!(BBSplusPseudonym::from_bytes(&pseudonym.to_bytes()).is_ok());
    for p in [G1Projective::IDENTITY, G1Projective::GENERATOR] {
        assert!(matches!(
            BBSplusPseudonym::from_bytes(&p.to_affine().to_compressed()),
            Err(Error::InvalidPseudonym)
        ));
    }
}

fn get_pseudonymsecrets(proof_json: &Value, name: &str) -> Vec<PseudonymSecret>{
    let nym_secrets: Vec<PseudonymSecret> = proof_json[name]
            .as_array()
            .unwrap()
            .iter()
            .map(pseudonym_secret)
            .collect::<Vec<PseudonymSecret>>();

    nym_secrets
}





/// Parses a scalar of the nym vectors. Some draft 05 vectors drop the leading zero of a
/// scalar (63 hex chars): pad it to 64.
fn pseudonym_secret(v: &Value) -> PseudonymSecret {
    PseudonymSecret::from_hex(&format!("{:0>64}", v.as_str().unwrap())).unwrap()
}

fn get_blind_factor(proof_json:&Value, name: &str) -> Option<BlindFactor> {
    proof_json[name].as_str().map(|b| {
        BlindFactor::from_bytes(&hex::decode(b).unwrap().try_into().unwrap()).unwrap()
    })
}
