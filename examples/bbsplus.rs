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

#[cfg(feature = "bbsplus")]
mod bbsplus_example {
    use elliptic_curve::hash2curve::ExpandMsg;
    use rand::Rng;
    use zkryptium::{
        bbsplus::ciphersuites::BbsCiphersuite,
        errors::Error,
        keys::pair::KeyPair,
        schemes::{
            algorithms::{BBSplus, Scheme},
            generics::{PoKSignature, Signature},
        },
        utils::util::bbsplus_utils::{generate_random_secret, get_messages_vec},
    };

    pub(crate) fn bbsplus_main<S: Scheme>() -> Result<(), Error>
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        const MSGS: [&str; 3] = [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6",
            "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90",
        ];

        log::info!("Messages: {:?}", MSGS);

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

        let messages: Vec<Vec<u8>> = MSGS.iter().map(|m| hex::decode(m).unwrap()).collect();
        log::info!("Signature Computation...");
        let signature = Signature::<BBSplus<S::Ciphersuite>>::sign(
            Some(&messages),
            issuer_sk,
            issuer_pk,
            Some(&header),
        )
        .unwrap();

        assert!(
            signature
                .verify(issuer_pk, Some(&messages), Some(&header))
                .is_ok(),
            "Signature verification FAILED!"
        );
        log::info!("Signature is VALID");

        //Holder receive nonce from Verifier
        let nonce_verifier = generate_random_secret(32);
        log::info!("Generate Nonce...");
        log::info!("Nonce: {}", hex::encode(&nonce_verifier));

        let disclosed_indexes = [0usize, 2usize];

        //Holder generates SPoK
        log::info!("Proof of Knowledge of the Signature Generation...");
        let proof = PoKSignature::<BBSplus<S::Ciphersuite>>::proof_gen(
            issuer_pk,
            &signature.to_bytes(),
            Some(&header),
            Some(&nonce_verifier),
            Some(&messages),
            Some(&disclosed_indexes),
        )
        .unwrap();

        //Verifier verifies SPok
        let disclosed_messages = get_messages_vec(&messages, &disclosed_indexes);

        log::info!("Proof of Knowledge of the Signature verification...");
        let proof_result = proof
            .proof_verify(
                &issuer_pk,
                Some(&disclosed_messages),
                Some(&disclosed_indexes),
                Some(&header),
                Some(&nonce_verifier),
            )
            .is_ok();
        assert!(
            proof_result,
            "Proof of Knowledge of the Signature Verification Failed!"
        );
        log::info!("Proof of Knowledge of the Signature is VALID!");

        Ok(())
    }
}

#[cfg(feature = "bbsplus")]
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

#[cfg(not(feature = "bbsplus"))]
fn main() {}
