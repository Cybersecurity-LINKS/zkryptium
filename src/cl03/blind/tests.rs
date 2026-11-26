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
use super::{CL03BlindSignInput, CL03RevealedMessages};
use crate::{
    cl03::{bases::Bases, keys::CL03CommitmentPublicKey, proof::CL03TrustedCommitment},
    errors::Error,
    keys::pair::KeyPair,
    schemes::algorithms::{Ciphersuite, Scheme, CL03},
    schemes::generics::{BlindSignature, Commitment, ZKPoK},
    utils::message::cl03_message::CL03Message,
};
use digest::Digest;

//Blind signature - CL1024-SHA256
#[test]
fn blind_sign_cl1024_sha256() {
    blind_sign::<CL03_CL1024_SHA256>();
}

//Blind Signature update - CL1024-SHA256
#[test]
fn update_signature_cl1024_sha256() {
    update_signature::<CL03_CL1024_SHA256>();
}

// CL03-01..04: invalid Prover input or inconsistent Signer input must return an error
// (or `false` from verify_proof) instead of panicking or being silently ignored.
#[test]
fn blind_sign_rejects_invalid_input_cl1024_sha256() {
    blind_sign_rejects_invalid_input::<CL03_CL1024_SHA256>();
}

fn blind_sign_rejects_invalid_input<S: Scheme>()
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
{
    let msgs = ["01", "02", "03"];
    let wrong_msgs = ["11", "12", "13"];
    let to_messages = |m: &[&str]| -> Vec<CL03Message> {
        m.iter()
            .map(|m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()))
            .collect()
    };
    let messages = to_messages(&msgs);
    let wrong_messages = to_messages(&wrong_msgs);

    let keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
    let (pk, sk) = (keypair.public_key(), keypair.private_key());
    let a_bases = Bases::generate(pk, msgs.len());
    let unrevealed = [0usize];
    let revealed_indexes = [1usize, 2];
    let revealed_messages = [messages[1].clone(), messages[2].clone()];
    let revealed = CL03RevealedMessages { messages: &revealed_messages, indexes: &revealed_indexes };

    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&messages, pk, &a_bases, Some(&unrevealed));
    let C = commitment.cl03Commitment();
    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, C, None, pk, &a_bases, &unrevealed);
    let sign = |zkpok: &ZKPoK<CL03<S::Ciphersuite>>, unrevealed: &[usize], input: CL03BlindSignInput<'_>| {
        BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(pk, sk, &a_bases, zkpok, C, unrevealed, input)
    };

    // Sanity: the valid input is accepted.
    assert!(sign(&zkpok, &unrevealed, CL03BlindSignInput { revealed: Some(revealed), ..Default::default() }).is_ok());

    // CL03-01: ZKPoK of a different commitment -> Err, not panic.
    let other = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&wrong_messages, pk, &a_bases, Some(&unrevealed));
    let other_zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
        &wrong_messages, other.cl03Commitment(), None, pk, &a_bases, &unrevealed,
    );
    assert!(matches!(
        sign(&other_zkpok, &unrevealed, CL03BlindSignInput::default()),
        Err(Error::BlindSignError(_))
    ));

    // CL03-04: proof shorter than the unrevealed indexes, or index outside the bases.
    assert!(!zkpok.verify_proof(C, None, pk, &a_bases, &[0, 1]));
    assert!(!zkpok.verify_proof(C, None, pk, &a_bases, &[7]));
    assert!(sign(&zkpok, &[0, 1], CL03BlindSignInput::default()).is_err());

    // CL03-03: the Signer asks for the trusted-commitment check, the proof lacks it.
    let tp_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(None, Some(msgs.len()));
    let tp_commitment =
        Commitment::<CL03<S::Ciphersuite>>::commit_with_commitment_pk(&messages, &tp_pk, Some(&unrevealed));
    let trusted = CL03TrustedCommitment { commitment: tp_commitment.cl03Commitment(), commitment_pk: &tp_pk };
    assert!(!zkpok.verify_proof(C, Some(trusted), pk, &a_bases, &unrevealed));
    assert!(sign(&zkpok, &unrevealed, CL03BlindSignInput { trusted_commitment: Some(trusted), ..Default::default() }).is_err());

    // CL03-02: revealed messages and indexes of different lengths, or index out of range.
    let short = CL03RevealedMessages { messages: &revealed_messages[..1], indexes: &revealed_indexes };
    let out_of_range = CL03RevealedMessages { messages: &revealed_messages, indexes: &[1, 9] };
    for bad in [short, out_of_range] {
        assert!(matches!(
            sign(&zkpok, &unrevealed, CL03BlindSignInput { revealed: Some(bad), ..Default::default() }),
            Err(Error::BlindSignError(_))
        ));
    }
    let blind_signature = sign(&zkpok, &unrevealed, CL03BlindSignInput { revealed: Some(revealed), ..Default::default() }).unwrap();
    for bad in [short, out_of_range] {
        assert!(matches!(
            blind_signature.update_signature(C, sk, pk, &a_bases, Some(bad)),
            Err(Error::UpdateSignatureError(_))
        ));
    }
}

fn blind_sign<S: Scheme>()
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
}

pub(crate) fn update_signature<S: Scheme>()
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
{
    const msgs: &[&str] = &[
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
    ];
    const updated_msgs: &[&str] = &[
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
        "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
        "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
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
    let updated_messages: Vec<CL03Message> = updated_msgs
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
    let revealed_updated_messages: Vec<CL03Message> = updated_messages
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

    let updated_signature = blind_signature.update_signature(
        commitment.cl03Commitment(),
        cl03_keypair.private_key(),
        cl03_keypair.public_key(),
        &a_bases,
        Some(CL03RevealedMessages {
            messages: &revealed_updated_messages,
            indexes: &revealed_message_indexes,
        }),
    ).unwrap();
    let unblinded_updated_signature = updated_signature.unblind_sign(&commitment);

    let verify = unblinded_updated_signature.verify_multiattr(
        cl03_keypair.public_key(),
        &a_bases,
        &updated_messages,
    );
    assert!(
        verify,
        "Error! The unblided signature verification should PASS!"
    );
}
