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

#[cfg(feature = "bbsplus_nym")]
mod bbsplus_example {
    use rand::RngExt;
    use zkryptium::{
        bbsplus::{
            ciphersuites::BbsCiphersuite,
            commitment::Message,
            proof::Disclosure,
            pseudonym::{BBSplusPseudonym, PseudonymSecret},
        },
        errors::Error,
        keys::pair::KeyPair,
        schemes::{
            algorithms::{BBSplus, Scheme},
            generics::{BlindPoKSignature, BlindSignature, Commitment},
        },
        utils::util::bbsplus_utils::generate_random_secret,
    };

    pub(crate) fn bbsplus_main<S: Scheme>() -> Result<(), Error>
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        const COMMITTED_MSGS: [(&str, &str); 2] = [
            ("HASH", "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
            ("RAW", "a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
        ];
        log::info!("Committed Messages: {:?}", COMMITTED_MSGS);

        const HEADER_HEX: &str = "11223344556677889900aabbccddeeff";
        let header = hex::decode(HEADER_HEX).unwrap();

        let mut rng = rand::rng();
        let key_material: Vec<u8> = (0..S::Ciphersuite::IKM_LEN).map(|_| rng.random()).collect();

        log::info!("Keypair Generation");
        let issuer_keypair =
            KeyPair::<BBSplus<S::Ciphersuite>>::generate(&key_material, None, None)?;

        let issuer_sk = issuer_keypair.private_key();
        log::info!("SK: {}", hex::encode(issuer_sk.to_bytes()));
        let issuer_pk = issuer_keypair.public_key();
        log::info!("PK: {}", hex::encode(issuer_pk.to_bytes()));

        log::info!("Prover generates the prover_nyms vector");
        let prover_nyms_len = 3;
        let prover_nyms = PseudonymSecret::random_vec(prover_nyms_len);

        log::info!("Computing pedersen commitment on messages with the pseudonym...");
        let committed_messages: Vec<Message> = COMMITTED_MSGS
            .iter()
            .map(|m| Message::try_from((m.0.to_string(), hex::decode(m.1).unwrap())))
            .collect::<Result<_, _>>()?;
        let (commitment_with_proof, secret_prover_blind) =
            Commitment::<BBSplus<S::Ciphersuite>>::commit_with_nym(
                Some(&committed_messages),
                prover_nyms.clone(),
            )?;

        log::info!("Send the commitment with the proof (and the nym vector length) to the Issuer");
        log::info!("Messages added by the Issuer to be signed");
        const MSGS: [(&str, &str); 3] = [
            ("HASH", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02"),
            ("HASH", "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6"),
            ("HASH", "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"),
        ];
        log::info!("Messages: {:?}", MSGS);
        let messages: Vec<Message> = MSGS
            .iter()
            .map(|m| Message::try_from((m.0.to_string(), hex::decode(m.1).unwrap())))
            .collect::<Result<_, _>>()?;

        log::info!("Signer generates the signer_nym_entropy");
        let signer_nym_entropy = PseudonymSecret::random();

        log::info!("Blind signature generation with Pseudonym...");
        let blind_sig = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign_with_nym(
            issuer_sk,
            issuer_pk,
            Some(&commitment_with_proof.to_bytes()),
            prover_nyms_len,
            Some(&header),
            &signer_nym_entropy,
            Some(&messages),
        )?;

        log::info!("Blind Signature with Pseudonym Verification...");
        // nym_secrets are secret: they stay with the Prover and are never logged or sent.
        let nym_secrets = blind_sig.verify_finalize_with_nym(
            issuer_pk,
            Some(&header),
            Some(&messages),
            Some(&committed_messages),
            prover_nyms,
            Some(&signer_nym_entropy),
            Some(&secret_prover_blind),
        )?;
        log::info!("Blind Signature with Pseudonym is VALID!");

        let context_id = b"verifier_context_id";

        //Holder receive nonce from Verifier
        log::info!("Generate Nonce...");
        let nonce_verifier = generate_random_secret(32);
        log::info!(
            "Verifier sends to the Holder, Nonce {} and context id {}",
            hex::encode(&nonce_verifier),
            String::from_utf8_lossy(context_id)
        );

        //Holder generates SPoK
        log::info!("Computation of a Zero-Knowledge proof-of-knowledge of a Blind Signature with Pseudonym");

        // Issuer messages: disclose the 1st, only commit to the 2nd, disclose the 3rd.
        // Blind messages: hide the 1st, disclose the 2nd. The nym secrets are never revealed.
        let issuer_message_disclosures =
            [Disclosure::Disclose, Disclosure::Commit, Disclosure::Disclose];
        let blind_message_disclosures = [Disclosure::Hide, Disclosure::Disclose];

        let (poks, pseudonym, add_zkp_info) =
            BlindPoKSignature::<BBSplus<S::Ciphersuite>>::proof_gen_with_nym(
                issuer_pk,
                &blind_sig.to_bytes(),
                Some(&header),
                Some(&nonce_verifier),
                &nym_secrets,
                context_id,
                Some(&messages),
                Some(&committed_messages),
                Some(&issuer_message_disclosures),
                Some(&blind_message_disclosures),
                Some(&secret_prover_blind),
            )?;
        // add_zkp_info stays with the Holder, never sent to the Verifier.
        log::info!(
            "Proof generated with {} committed disclosure(s)",
            add_zkp_info.commitment_rands.len()
        );

        let poks_bytes = poks.to_bytes();
        let pseudonym_bytes = pseudonym.to_bytes();
        log::info!("Holder sends the proof to the Verifier: {}", hex::encode(&poks_bytes));
        log::info!("Holder sends the pseudonym to the Verifier: {}", hex::encode(&pseudonym_bytes));

        //Verifier verifies SPok with Pseudonym
        log::info!("Signature Proof of Knowledge with Pseudonym verification...");
        let message_disclosures: Vec<Disclosure> = issuer_message_disclosures
            .iter()
            .chain(&blind_message_disclosures)
            .copied()
            .collect();
        let disclosed_messages: Vec<Message> = messages
            .iter()
            .chain(&committed_messages)
            .zip(&message_disclosures)
            .filter(|(_, d)| **d == Disclosure::Disclose)
            .map(|(m, _)| m.clone())
            .collect();
        let commitments_count = message_disclosures
            .iter()
            .filter(|d| **d == Disclosure::Commit)
            .count();

        let received_poks =
            BlindPoKSignature::<BBSplus<S::Ciphersuite>>::from_bytes(&poks_bytes, commitments_count)?;
        let received_pseudonym = BBSplusPseudonym::from_bytes(&pseudonym_bytes)?;
        received_poks.proof_verify_with_nym(
            issuer_pk,
            Some(&header),
            Some(&nonce_verifier),
            &received_pseudonym,
            context_id,
            prover_nyms_len,
            Some(messages.len()),
            Some(&disclosed_messages),
            Some(&message_disclosures),
        )?;
        log::info!("Signature Proof of Knowledge with Pseudonym is VALID!");

        Ok(())
    }
}

#[cfg(feature = "bbsplus_nym")]
fn main() -> std::process::ExitCode {
    use crate::bbsplus_example::bbsplus_main;
    use std::{env, process::ExitCode};
    use zkryptium::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};

    dotenvy::dotenv().ok();
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!(
            "Usage: {} <cipher_suite>
                Ciphersuites:
                    - BLS12-381-SHA-256
                    - BLS12-381-SHAKE-256",
            args[0]
        );
        return ExitCode::FAILURE;
    }

    let cipher_suite = &args[1];

    let result = match cipher_suite.as_str() {
        "BLS12-381-SHA-256" => {
            println!("\n");
            log::info!("Ciphersuite: BLS12-381-SHA-256");
            bbsplus_main::<BbsBls12381Sha256>()
        }
        "BLS12-381-SHAKE-256" => {
            println!("\n");
            log::info!("Ciphersuite: BLS12-381-SHAKE-256");
            bbsplus_main::<BbsBls12381Shake256>()
        }
        _ => {
            eprintln!("Unknown cipher suite: {}", cipher_suite);
            return ExitCode::FAILURE;
        }
    };

    // Report the library error (with its details) and exit with a non-zero status,
    // instead of silently discarding it.
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Example failed: {e} ({e:?})");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "bbsplus_nym"))]
fn main() {}
