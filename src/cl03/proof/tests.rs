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

use crate::cl03::ciphersuites::CLCiphersuite;
use crate::schemes::algorithms::CL03_CL1024_SHA256;
use super::CL03TrustedCommitment;
use crate::{
    cl03::{
        bases::Bases,
        blind::{CL03BlindSignInput, CL03RevealedMessages},
        keys::CL03CommitmentPublicKey,
    },
    keys::pair::KeyPair,
    schemes::{
        algorithms::{Ciphersuite, Scheme, CL03},
        generics::{BlindSignature, Commitment, PoKSignature, ZKPoK},
    },
    utils::message::cl03_message::CL03Message,
};
use digest::Digest;

//Proof of knowledge of secrets (ZKPoK) - CL1024-SHA256
#[test]
fn zkpok_cl1024_sha256() {
    zkpok::<CL03_CL1024_SHA256>();
}

//Signature Proof of Knowledge - CL1024-SHA256
#[test]
fn spok_cl1024_sha256() {
    spok::<CL03_CL1024_SHA256>();
}

// CL03-11: from a signature (e, s, v) on m, (e, s, v * a_i^k) is a valid signature on
// m_i + k*e. Messages outside [0, 2^lm) must be rejected when verifying (T1), when
// verifying a SPoK that reveals them (T5) and when signing.
#[test]
fn shifted_messages_rejected_cl1024_sha256() {
    use crate::{cl03::signature::CL03Signature, errors::Error, schemes::generics::Signature};
    use rug::Integer;
    type CS = <CL03_CL1024_SHA256 as Scheme>::Ciphersuite;

    let messages: Vec<CL03Message> = ["01", "02", "03"]
        .iter()
        .map(|m| CL03Message::map_message_to_integer_as_hash::<CS>(&hex::decode(m).unwrap()))
        .collect();
    let keypair = KeyPair::<CL03<CS>>::generate();
    let (pk, sk) = (keypair.public_key(), keypair.private_key());
    let a_bases = Bases::generate(pk, messages.len());
    let signature = Signature::<CL03<CS>>::sign_multiattr(pk, sk, &a_bases, &messages).unwrap();
    let CL03Signature { e, s, v } = signature.cl03Signature().clone();
    // (e, s, v * a_i^k) and the messages with m_i + k*e.
    let shifted = |i: usize, k: i32| {
        let ak = Integer::from(a_bases.0[i].pow_mod_ref(&Integer::from(k), &pk.N).unwrap());
        let sig = CL03Signature { e: e.clone(), s: s.clone(), v: (v.clone() * ak) % &pk.N };
        let mut msgs = messages.clone();
        msgs[i] = CL03Message::new(messages[i].value.clone() + e.clone() * k);
        (sig, msgs)
    };

    // T1: the shifted signature verifies algebraically, but the message is out of range.
    for k in [1, -1, 5] {
        let (sig, msgs) = shifted(0, k);
        assert!(!msgs[0].is_in_range::<CS>());
        let sig = Signature::<CL03<CS>>::CL03(sig);
        assert!(!sig.verify_multiattr(pk, &a_bases, &msgs), "k = {k}");
    }
    let single_bases = Bases(vec![a_bases.0[0].clone()]);
    let single = Signature::<CL03<CS>>::sign(pk, sk, &single_bases, &messages[0]).unwrap();
    let CL03Signature { e: e1, s: s1, v: v1 } = single.cl03Signature().clone();
    let forged = Signature::<CL03<CS>>::CL03(CL03Signature {
        e: e1.clone(),
        s: s1,
        v: (v1 * &single_bases.0[0]) % &pk.N,
    });
    assert!(!forged.verify(pk, &single_bases, &CL03Message::new(messages[0].value.clone() + e1)));

    // T5: SPoK revealing m1 + k*e, generated honestly from the shifted signature.
    let unrevealed = [0usize];
    let verifier_pk = CL03CommitmentPublicKey::generate::<CS>(Some(pk.N.clone()), Some(messages.len()));
    for k in [-1, 1] {
        let (sig, msgs) = shifted(1, k);
        let spok = PoKSignature::<CL03<CS>>::proof_gen(&sig, &verifier_pk, pk, &a_bases, &msgs, &unrevealed);
        let revealed = [msgs[1].clone(), msgs[2].clone()];
        assert!(!spok.proof_verify(&verifier_pk, pk, &a_bases, &revealed, &unrevealed, msgs.len()), "k = {k}");
    }

    // Signing out-of-range messages is refused.
    for bad in [Integer::from(-1), Integer::from(1) << CS::lm] {
        let mut msgs = messages.clone();
        msgs[0] = CL03Message::new(bad);
        assert!(matches!(
            Signature::<CL03<CS>>::sign_multiattr(pk, sk, &a_bases, &msgs),
            Err(Error::SignatureGenerationError(_))
        ));
        assert!(Signature::<CL03<CS>>::sign(pk, sk, &a_bases, &msgs[0]).is_err());
        let revealed = [msgs[0].clone()];
        let commitment = Commitment::<CL03<CS>>::commit_with_pk(&messages, pk, &a_bases, Some(&[1, 2]));
        let zkpok = ZKPoK::<CL03<CS>>::generate_proof(&messages, commitment.cl03Commitment(), None, pk, &a_bases, &[1, 2]);
        assert!(matches!(
            BlindSignature::<CL03<CS>>::blind_sign(
                pk,
                sk,
                &a_bases,
                &zkpok,
                commitment.cl03Commitment(),
                &[1, 2],
                CL03BlindSignInput {
                    revealed: Some(CL03RevealedMessages { messages: &revealed, indexes: &[0] }),
                    ..Default::default()
                },
            ),
            Err(Error::BlindSignError(_))
        ));
    }
    // The largest valid message is still accepted.
    let mut msgs = messages.clone();
    msgs[0] = CL03Message::new((Integer::from(1) << CS::lm) - 1);
    let sig = Signature::<CL03<CS>>::sign_multiattr(pk, sk, &a_bases, &msgs).unwrap();
    assert!(sig.verify_multiattr(pk, &a_bases, &msgs));
}

// CL03-05..07: proofs, signatures and keys come from other parties. Malformed values found
// by fuzzing (non-invertible group elements, truncated vectors, short byte strings) must
// make the verifiers return false / the parsers return an error, not panic.
#[test]
fn verifiers_reject_malformed_input_cl1024_sha256() {
    use crate::{cl03::keys::CL03PublicKey, errors::Error, schemes::generics::Signature};
    use serde_json::Value;
    type CS = <CL03_CL1024_SHA256 as Scheme>::Ciphersuite;

    // Returns `v` with the JSON value at `path` replaced by `new`.
    fn edit(v: &Value, path: &str, new: Value) -> Value {
        let mut v = v.clone();
        *v.pointer_mut(path).unwrap_or_else(|| panic!("no {path}")) = new;
        v
    }
    fn truncated(v: &Value, path: &str) -> Value {
        let mut a = v.pointer(path).unwrap().as_array().unwrap().clone();
        a.pop();
        edit(v, path, Value::Array(a))
    }
    let zero = || Value::String("0".into());

    let messages: Vec<CL03Message> = ["01", "02", "03"]
        .iter()
        .map(|m| CL03Message::map_message_to_integer_as_hash::<CS>(&hex::decode(m).unwrap()))
        .collect();
    let keypair = KeyPair::<CL03<CS>>::generate();
    let (pk, sk) = (keypair.public_key(), keypair.private_key());
    let a_bases = Bases::generate(pk, messages.len());
    let unrevealed = [0usize];
    let revealed_indexes = [1usize, 2];
    let revealed_messages = [messages[1].clone(), messages[2].clone()];

    // ZKPoK (Prover -> Signer).
    let commitment = Commitment::<CL03<CS>>::commit_with_pk(&messages, pk, &a_bases, Some(&unrevealed));
    let C = commitment.cl03Commitment();
    let zkpok = ZKPoK::<CL03<CS>>::generate_proof(&messages, C, None, pk, &a_bases, &unrevealed);
    let zj = serde_json::to_value(&zkpok).unwrap();
    for bad in [
        edit(&zj, "/CL03/proof_commited_msgs/s1", Value::Array(vec![])),
        edit(&zj, "/CL03/range_proof_r/proof_of_tolerance/proof_of_square_a/F/value", zero()),
        edit(&zj, "/CL03/range_proofs_mi/0/proof_of_tolerance/E_a_1/value", zero()),
    ] {
        let bad: ZKPoK<CL03<CS>> = serde_json::from_value(bad).unwrap();
        assert!(!bad.verify_proof(C, None, pk, &a_bases, &unrevealed));
    }

    // SPoK (Prover -> Verifier).
    let blind_signature = BlindSignature::<CL03<CS>>::blind_sign(
        pk,
        sk,
        &a_bases,
        &zkpok,
        C,
        &unrevealed,
        CL03BlindSignInput {
            revealed: Some(CL03RevealedMessages { messages: &revealed_messages, indexes: &revealed_indexes }),
            ..Default::default()
        },
    )
    .unwrap();
    let signature = blind_signature.unblind_sign(&commitment);
    let verifier_pk = CL03CommitmentPublicKey::generate::<CS>(Some(pk.N.clone()), Some(messages.len()));
    let spok = PoKSignature::<CL03<CS>>::proof_gen(
        signature.cl03Signature(), &verifier_pk, pk, &a_bases, &messages, &unrevealed,
    );
    let verify = |p: &PoKSignature<CL03<CS>>| {
        p.proof_verify(&verifier_pk, pk, &a_bases, &revealed_messages, &unrevealed, messages.len())
    };
    assert!(verify(&spok));
    let sj = serde_json::to_value(&spok).unwrap();
    for bad in [
        edit(&sj, "/CL03/spok/Cx/value/value", zero()),
        edit(&sj, "/CL03/spok/s_5", Value::Array(vec![])),
        truncated(&sj, "/CL03/proofs_commited_mi"),
        truncated(&sj, "/CL03/range_proofs_commited_mi"),
        edit(&sj, "/CL03/range_proof_e/proof_of_tolerance/E_b_1/value", zero()),
    ] {
        let bad: PoKSignature<CL03<CS>> = serde_json::from_value(bad).unwrap();
        assert!(!verify(&bad));
    }

    // Signature (Signer -> Prover) and byte parsers.
    assert!(signature.verify_multiattr(pk, &a_bases, &messages));
    let too_many: Vec<CL03Message> = messages.iter().chain(&messages).cloned().collect();
    assert!(!signature.verify_multiattr(pk, &a_bases, &too_many));
    let gj = serde_json::to_value(&signature).unwrap();
    let e = gj.pointer("/CL03/e/value").unwrap().as_str().unwrap().to_owned();
    let bad = edit(&edit(&gj, "/CL03/v/value", zero()), "/CL03/e/value", Value::String(format!("-{e}")));
    let bad: Signature<CL03<CS>> = serde_json::from_value(bad).unwrap();
    assert!(!bad.verify_multiattr(pk, &a_bases, &messages));
    assert!(!bad.verify(pk, &a_bases, &messages[0]));
    assert!(matches!(Signature::<CL03<CS>>::from_bytes(&[1, 2, 3]), Err(Error::InvalidSignature)));
    assert!(matches!(
        CL03PublicKey::from_bytes::<CL03_CL1024_SHA256>(&[1, 2, 3]),
        Err(Error::KeyDeserializationError)
    ));
}

fn zkpok<S: Scheme>()
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
{
    const msgs: &[&str] = &[
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
    ];

    const wrong_msgs: &[&str] = &[
        "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
    ];

    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
    let a_bases = Bases::generate(cl03_keypair.public_key(), msgs.len());

    let messages: Vec<CL03Message> = msgs
        .iter()
        .map(|&m| {
            CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                &hex::decode(m).unwrap(),
            )
        })
        .collect();
    let wrong_messages: Vec<CL03Message> = wrong_msgs
        .iter()
        .map(|&m| {
            CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                &hex::decode(m).unwrap(),
            )
        })
        .collect();

    let unrevealed_message_indexes = [0usize];
    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(
        &messages,
        cl03_keypair.public_key(),
        &a_bases,
        Some(&unrevealed_message_indexes),
    );
    let wrong_commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(
        &wrong_messages,
        cl03_keypair.public_key(),
        &a_bases,
        Some(&unrevealed_message_indexes),
    );

    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
        &messages,
        commitment.cl03Commitment(),
        None,
        cl03_keypair.public_key(),
        &a_bases,
        &unrevealed_message_indexes,
    );

    let valid = zkpok.verify_proof(
        commitment.cl03Commitment(),
        None,
        cl03_keypair.public_key(),
        &a_bases,
        &unrevealed_message_indexes,
    );

    assert!(valid, "Error! ZKPoK verification should PASS");

    let valid = zkpok.verify_proof(
        wrong_commitment.cl03Commitment(),
        None,
        cl03_keypair.public_key(),
        &a_bases,
        &unrevealed_message_indexes,
    );

    assert!(!valid, "Error! ZKPok verification should FAIL");

    //Trusted Party Commitment

    let trusted_party_commitment_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(
        None,
        Some(msgs.len()),
    );
    let trusted_party_commitment =
        Commitment::<CL03<S::Ciphersuite>>::commit_with_commitment_pk(
            &messages,
            &trusted_party_commitment_pk,
            Some(&unrevealed_message_indexes),
        );
    let trusted_party_commitment_wrong =
        Commitment::<CL03<S::Ciphersuite>>::commit_with_commitment_pk(
            &wrong_messages,
            &trusted_party_commitment_pk,
            Some(&unrevealed_message_indexes),
        );

    let zkpok2 = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
        &messages,
        commitment.cl03Commitment(),
        Some(CL03TrustedCommitment {
            commitment: trusted_party_commitment.cl03Commitment(),
            commitment_pk: &trusted_party_commitment_pk,
        }),
        cl03_keypair.public_key(),
        &a_bases,
        &unrevealed_message_indexes,
    );

    let valid = zkpok2.verify_proof(
        commitment.cl03Commitment(),
        Some(CL03TrustedCommitment {
            commitment: trusted_party_commitment.cl03Commitment(),
            commitment_pk: &trusted_party_commitment_pk,
        }),
        cl03_keypair.public_key(),
        &a_bases,
        &unrevealed_message_indexes,
    );

    assert!(valid, "Error! ZKPoK verification should PASS");

    let zkpok2_wrong_tp_commitment = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
        &messages,
        commitment.cl03Commitment(),
        Some(CL03TrustedCommitment {
            commitment: trusted_party_commitment_wrong.cl03Commitment(),
            commitment_pk: &trusted_party_commitment_pk,
        }),
        cl03_keypair.public_key(),
        &a_bases,
        &unrevealed_message_indexes,
    );

    let valid = zkpok2_wrong_tp_commitment.verify_proof(
        commitment.cl03Commitment(),
        Some(CL03TrustedCommitment {
            commitment: trusted_party_commitment.cl03Commitment(),
            commitment_pk: &trusted_party_commitment_pk,
        }),
        cl03_keypair.public_key(),
        &a_bases,
        &unrevealed_message_indexes,
    );

    assert!(!valid, "Error! ZKPoK verification should FAIL");
}

pub(crate) fn spok<S: Scheme>()
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
{
    const msgs: &[&str] = &[
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
    ];
    // const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const wrong_msgs: &[&str] = &[
        "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
        "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
    ];

    let n_attr = msgs.len();
    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
    let a_bases = Bases::generate(cl03_keypair.public_key(), n_attr);

    let messages: Vec<CL03Message> = msgs
        .iter()
        .map(|&m| {
            CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                &hex::decode(m).unwrap(),
            )
        })
        .collect();
    // let msg_intger = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(msg).unwrap());
    // let messages = [msg_intger.clone()];
    let wrong_messages: Vec<CL03Message> = wrong_msgs
        .iter()
        .map(|&m| {
            CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                &hex::decode(m).unwrap(),
            )
        })
        .collect();

    let unrevealed_message_indexes = [0usize];
    let revealed_message_indexes = [1usize, 2usize];
    let revealed_messages: Vec<CL03Message> = messages
        .iter()
        .enumerate()
        .filter(|&(i, _)| revealed_message_indexes.contains(&i))
        .map(|(_, m)| m.clone())
        .collect();
    let revealed_messages_wrong: Vec<CL03Message> = wrong_messages
        .iter()
        .enumerate()
        .filter(|&(i, _)| revealed_message_indexes.contains(&i))
        .map(|(_, m)| m.clone())
        .collect();

    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(
        &messages,
        cl03_keypair.public_key(),
        &a_bases,
        Some(&unrevealed_message_indexes),
    );

    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
        &messages,
        commitment.cl03Commitment(),
        None,
        cl03_keypair.public_key(),
        &a_bases,
        &unrevealed_message_indexes,
    );

    let blind_signature = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(
        cl03_keypair.public_key(),
        cl03_keypair.private_key(),
        &a_bases,
        &zkpok,
        commitment.cl03Commitment(),
        &unrevealed_message_indexes,
        CL03BlindSignInput {
            revealed: Some(CL03RevealedMessages {
                messages: &revealed_messages,
                indexes: &revealed_message_indexes,
            }),
            ..Default::default()
        },
    ).unwrap();
    let unblided_signature = blind_signature.unblind_sign(&commitment);
    let verify =
        unblided_signature.verify_multiattr(cl03_keypair.public_key(), &a_bases, &messages);

    assert!(
        verify,
        "Error! The unblided signature verification should PASS!"
    );

    let blind_signature_wrong = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(
        cl03_keypair.public_key(),
        cl03_keypair.private_key(),
        &a_bases,
        &zkpok,
        commitment.cl03Commitment(),
        &unrevealed_message_indexes,
        CL03BlindSignInput {
            revealed: Some(CL03RevealedMessages {
                messages: &revealed_messages_wrong,
                indexes: &revealed_message_indexes,
            }),
            ..Default::default()
        },
    ).unwrap();
    let unblided_signature_wrong = blind_signature_wrong.unblind_sign(&commitment);
    let verify = unblided_signature_wrong.verify_multiattr(
        cl03_keypair.public_key(),
        &a_bases,
        &messages,
    );

    assert!(
        !verify,
        "Error! The unblinded signature verification SHOULD FAIL!"
    );

    let commitment_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(
        Some(cl03_keypair.public_key().N.clone()),
        Some(n_attr),
    );

    let signature_pok = PoKSignature::<CL03<S::Ciphersuite>>::proof_gen(
        unblided_signature.cl03Signature(),
        &commitment_pk,
        cl03_keypair.public_key(),
        &a_bases,
        &messages,
        &unrevealed_message_indexes,
    );
    let valid_proof = signature_pok.proof_verify(
        &commitment_pk,
        cl03_keypair.public_key(),
        &a_bases,
        &revealed_messages,
        &unrevealed_message_indexes,
        n_attr,
    );

    assert!(
        valid_proof,
        "Error! The signature proof of knowledge should PASS!"
    );

    let signature_pok = PoKSignature::<CL03<S::Ciphersuite>>::proof_gen(
        unblided_signature.cl03Signature(),
        &commitment_pk,
        cl03_keypair.public_key(),
        &a_bases,
        &messages,
        &unrevealed_message_indexes,
    );
    let valid_proof = signature_pok.proof_verify(
        &commitment_pk,
        cl03_keypair.public_key(),
        &a_bases,
        &revealed_messages_wrong,
        &unrevealed_message_indexes,
        n_attr,
    );

    assert!(
        !valid_proof,
        "Error! The signature proof of knowledge should FAIL!"
    );
}
