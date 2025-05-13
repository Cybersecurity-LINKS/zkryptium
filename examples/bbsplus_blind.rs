// Copyright 2025 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(feature = "bbsplus_blind")]
mod bbsplus_example {
    use elliptic_curve::hash2curve::ExpandMsg;
    use rand::Rng;
    use zkryptium::{
        bbsplus::ciphersuites::BbsCiphersuite,
        errors::Error,
        keys::pair::KeyPair,
        schemes::{
            algorithms::{BBSplus, Scheme},
            generics::{BlindSignature, Commitment, PoKSignature},
        },
        utils::util::bbsplus_utils::generate_random_secret,
    };

    pub(crate) fn bbsplus_main<S: Scheme>() -> Result<(), Error>
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        const COMMITTED_MSGS: [&str; 2] = [
            "5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3",
            "a75d8b634891af92282cc81a675972d1929d3149863c1fc0",
        ];
        log::info!("Committed Messages: {:?}", COMMITTED_MSGS);

        const HEADER_HEX: &str = "11223344556677889900aabbccddeeff";
        let header = hex::decode(HEADER_HEX).unwrap();

        let mut rng = rand::thread_rng();
        let key_material: Vec<u8> = (0..S::Ciphersuite::IKM_LEN).map(|_| rng.gen()).collect();

        log::info!("Keypair Generation");
        let issuer_keypair =
            KeyPair::<BBSplus<S::Ciphersuite>>::generate(&key_material, None, None)?;

        let issuer_sk = issuer_keypair.private_key();
        log::info!("SK: {}", hex::encode(issuer_sk.to_bytes()));
        let issuer_pk = issuer_keypair.public_key();
        log::info!("PK: {}", hex::encode(issuer_pk.to_bytes()));

        log::info!("Computing pedersen commitment on messages with the proof and the secret_prover_blind...");
        let committed_messages: Vec<Vec<u8>> = COMMITTED_MSGS
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect();
        let (commitment_with_proof, secret_prover_blind) =
            Commitment::<BBSplus<S::Ciphersuite>>::commit(Some(&committed_messages))?;

        log::info!("Send the commitment with the proof to the Issuer");
        log::info!("Messages added by the Issuer to be signed");
        const MSGS: [&str; 3] = [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6",
            "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90",
        ];
        log::info!("Messages: {:?}", MSGS);
        let messages: Vec<Vec<u8>> = MSGS.iter().map(|m| hex::decode(m).unwrap()).collect();

        log::info!("Blind signature generation...");
        let blind_signature = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(
            issuer_sk,
            issuer_pk,
            Some(&commitment_with_proof.to_bytes()),
            Some(&header),
            Some(&messages),
        )?;

        log::info!("Blind Signature Verification...");
        assert!(blind_signature
            .verify_blind_sign(
                issuer_pk,
                Some(&header),
                Some(&messages),
                Some(&committed_messages),
                Some(&secret_prover_blind),
            )
            .is_ok());
        log::info!("Blind Signature is VALID!");

        //Holder receive nonce from Verifier
        log::info!("Generate Nonce...");
        let nonce_verifier = generate_random_secret(32);
        log::info!(
            "Verifier sends Nonce to the Holder: {}",
            hex::encode(&nonce_verifier)
        );

        //Holder generates SPoK
        log::info!("Computation of a Zero-Knowledge proof-of-knowledge of a Blind Signature");

        let disclosed_indexes = [0usize, 2usize];
        let disclosed_commitment_indexes = [1usize];
        let poks = PoKSignature::<BBSplus<S::Ciphersuite>>::blind_proof_gen(
            issuer_pk,
            &blind_signature.to_bytes(),
            Some(&header),
            Some(&nonce_verifier),
            Some(&messages),
            Some(&committed_messages),
            Some(&disclosed_indexes),
            Some(&disclosed_commitment_indexes),
            Some(&secret_prover_blind)
        )?;

        //Verifier verifies SPok
        log::info!("Signature Proof of Knowledge verification...");
        let disclosed_messages = disclosed_indexes
            .iter()
            .map(|&i| messages[i].clone())
            .collect::<Vec<_>>();
        let disclosed_committed_messages = disclosed_commitment_indexes
            .iter()
            .map(|&i| committed_messages[i].clone())
            .collect::<Vec<_>>();
        let poks_verification_result = poks
            .blind_proof_verify(
                issuer_pk,
                Some(&header),
                Some(&nonce_verifier),
                Some(messages.len()),
                Some(&disclosed_messages),
                Some(&disclosed_committed_messages),
                Some(&disclosed_indexes),
                Some(&disclosed_commitment_indexes),
            )
            .is_ok();
        assert!(
            poks_verification_result,
            "Signature Proof of Knowledge Verification Failed!"
        );
        log::info!("Signature Proof of Knowledge is VALID!");

        Ok(())
    }
}

#[cfg(feature = "bbsplus_blind")]
fn main() {
    use crate::bbsplus_example::bbsplus_main;
    use std::env;
    use zkryptium::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};

    dotenvy::dotenv().ok();
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!(
            "Usage: {} <cipher_suite>
                Ciphersuites:
                    - BLS12-381-SHA-256
                    - BLS12-381-SHAKE-256",
            args[0]
        );
        return;
    }

    let cipher_suite = &args[1];

    match cipher_suite.as_str() {
        "BLS12-381-SHA-256" => {
            println!("\n");
            log::info!("Ciphersuite: BLS12-381-SHA-256");
            let _ = bbsplus_main::<BbsBls12381Sha256>();
        }
        "BLS12-381-SHAKE-256" => {
            println!("\n");
            log::info!("Ciphersuite: BLS12-381-SHAKE-256");
            let _ = bbsplus_main::<BbsBls12381Shake256>();
        }
        _ => {
            println!("Unknown cipher suite: {}", cipher_suite);
            // Handle other cipher suites or raise an error if necessary
        }
    }
}

#[cfg(not(feature = "bbsplus_blind"))]
fn main() {}
