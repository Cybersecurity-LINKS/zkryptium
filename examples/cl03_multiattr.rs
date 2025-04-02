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

#[cfg(feature = "cl03")]
mod cl03_example {
    use digest::Digest;
    use zkryptium::cl03::bases::Bases;
    use zkryptium::cl03::ciphersuites::{CL1024Sha256, CLCiphersuite};
    use zkryptium::cl03::keys::CL03CommitmentPublicKey;
    use zkryptium::keys::pair::KeyPair;
    use zkryptium::schemes::algorithms::{Ciphersuite, Scheme, CL03};
    use zkryptium::schemes::generics::{PoKSignature, Signature};
    use zkryptium::utils::message::cl03_message::CL03Message;

    pub(crate) fn cl03_main<S: Scheme>()
    where
        S::Ciphersuite: CLCiphersuite,
        <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
    {
        const MSGS: &[&str] = &[
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
        ];

        log::info!("Messages: {:?}", MSGS);
        log::info!("Keypair Generation");

        let issuer_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();

        log::info!("Bases generation");

        let a_bases = Bases::generate(issuer_keypair.public_key(), MSGS.len());
        let messages: Vec<CL03Message> = MSGS
            .iter()
            .map(|&m| {
                CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                    &hex::decode(m).unwrap(),
                )
            })
            .collect();

        let undisclosed_message_indexes = [1];
        let revealed_message_indexes = [0, 2];
        let unrevealed_message_indexes = undisclosed_message_indexes;

        let signature = Signature::<CL03<CL1024Sha256>>::sign_multiattr(
            issuer_keypair.public_key(),
            issuer_keypair.private_key(),
            &a_bases,
            &messages
        );
        let verify = signature.verify_multiattr(issuer_keypair.public_key(), &a_bases, &messages);

        log::info!("Bases:\t{:?}", a_bases);
        log::info!("Messages:\t{:?}", messages);

        assert!(
            verify,
            "Error! The signature verification should PASS!"
        );
        log::info!("Signature is VALID!");

        let (sd_messages, sd_bases) = signature.disclose_selectively(&messages, a_bases.clone(), issuer_keypair.public_key(), undisclosed_message_indexes.as_slice());

        log::info!("SDBases:\t{:?}", sd_bases);
        log::info!("SDMessages:\t{:?}", sd_messages);

        let verify = signature.verify_multiattr(issuer_keypair.public_key(), &sd_bases, &sd_messages);

        assert!(
            verify,
            "Error! The signature verification should PASS!"
        );

        log::info!("Signature for Selective Disclosure is VALID!");
        let revealed_messages: Vec<CL03Message> = messages
            .iter()
            .enumerate()
            .filter(|&(i, _)| revealed_message_indexes.contains(&i))
            .map(|(_, m)| m.clone())
            .collect();

        // Verifier generates its pk
        log::info!("Generation of a Commitment Public Key for the computation of the SPoK");
        let verifier_commitment_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(
            Some(issuer_keypair.public_key().N.clone()),
            Some(MSGS.len()),
        );

        // Holder compute the Signature Proof of Knowledge
        log::info!("Computation of a Zero-Knowledge proof-of-knowledge of a signature");
        let signature_pok = PoKSignature::<CL03<S::Ciphersuite>>::proof_gen(
            signature.cl03Signature(),
            &verifier_commitment_pk,
            issuer_keypair.public_key(),
            &a_bases,
            &messages,
            &unrevealed_message_indexes,
        );

        //Verifier verifies the Signature Proof of Knowledge
        log::info!("Signature Proof of Knowledge verification...");
        let valid_proof = signature_pok.proof_verify(
            &verifier_commitment_pk,
            issuer_keypair.public_key(),
            &a_bases,
            &revealed_messages,
            &unrevealed_message_indexes,
            MSGS.len(),
        );

        assert!(
            valid_proof,
            "Error! The signature proof of knowledge should PASS!"
        );
        log::info!("Signature Proof of Knowledge is VALID!");
    }
}

#[cfg(feature = "cl03")]
fn main() {
    use std::env;
    use zkryptium::schemes::algorithms::{CL03_CL1024_SHA256, CL03_CL2048_SHA256, CL03_CL3072_SHA256};

    dotenvy::dotenv().ok();
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!(
            "Usage: {} <cipher_suite>
                Ciphersuites:
                    - CL1024-SHA-256
                    - CL2048-SHA-256
                    - CL3072-SHA-256",
            args[0]
        );
        return;
    }

    let cipher_suite = &args[1];

    match cipher_suite.as_str() {
        "CL1024-SHA-256" => {
            println!("\n");
            log::info!("Ciphersuite: CL1024-SHA-256");
            cl03_example::cl03_main::<CL03_CL1024_SHA256>();
        }
        "CL2048-SHA-256" => {
            println!("\n");
            log::info!("Ciphersuite: CL2048-SHA-256");
            cl03_example::cl03_main::<CL03_CL2048_SHA256>();
        }
        "CL3072-SHA-256" => {
            println!("\n");
            log::info!("Ciphersuite: CL3072-SHA-256");
            cl03_example::cl03_main::<CL03_CL3072_SHA256>();
        }
        _ => {
            println!("Unknown cipher suite: {}", cipher_suite);
            // Handle other cipher suites or raise an error if necessary
        }
    }
}

#[cfg(not(feature = "cl03"))]
fn main() {}
