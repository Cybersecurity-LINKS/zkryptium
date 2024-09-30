// Copyright 2023 Fondazione LINKS

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
    use zkryptium::{
        cl03::{bases::Bases, ciphersuites::CLCiphersuite, keys::CL03CommitmentPublicKey},
        keys::pair::KeyPair,
        schemes::algorithms::{Ciphersuite, Scheme, CL03},
        schemes::generics::{BlindSignature, Commitment, PoKSignature, ZKPoK},
        utils::message::cl03_message::CL03Message,
    };
    use zkryptium::cl03::ciphersuites::CL1024Sha256;
    use zkryptium::schemes::generics::Signature;

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

        let unrevealed_message_indexes = [0usize];
        let revealed_message_indexes = [1usize, 2usize];
        let revealed_messages: Vec<CL03Message> = messages
            .iter()
            .enumerate()
            .filter(|&(i, _)| revealed_message_indexes.contains(&i))
            .map(|(_, m)| m.clone())
            .collect();

        let signature = Signature::<CL03<CL1024Sha256>>::sign_multiattr(
            issuer_keypair.public_key(),
            issuer_keypair.private_key(),
            &a_bases,
            &messages
        );

        let verify = signature.verify_multiattr(issuer_keypair.public_key(), &a_bases, &messages);

        assert!(
            verify,
            "Error! The unblided signature verification should PASS!"
        );
        log::info!("Signature is VALID!");
    }
}

#[cfg(feature = "cl03")]
fn main() {
    use std::env;
    use zkryptium::schemes::algorithms::CL03_CL1024_SHA256;

    dotenv::dotenv().ok();
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!(
            "Usage: {} <cipher_suite>
                Ciphersuites:
                    - CL1024-SHA-256",
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
        _ => {
            println!("Unknown cipher suite: {}", cipher_suite);
            // Handle other cipher suites or raise an error if necessary
        }
    }
}

#[cfg(not(feature = "cl03"))]
fn main() {}
