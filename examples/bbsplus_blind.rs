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


#[cfg(feature = "bbsplus")]
mod bbsplus_example {
    use elliptic_curve::hash2curve::ExpandMsg;
    use rand::Rng;
    use zkryptium::{utils::{message::BBSplusMessage, util::bbsplus_utils::generate_nonce}, keys::pair::KeyPair, bbsplus::{generators::Generators, ciphersuites::BbsCiphersuite}, schemes::algorithms::{BBSplus, Scheme, Ciphersuite}, schemes::generics::{Commitment, BlindSignature, PoKSignature, ZKPoK}, errors::Error};



    pub(crate) fn bbsplus_main<S: Scheme>() -> Result<(), Error>
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        const msgs: [&str; 3] = ["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6", "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"];
        
        log::info!("Messages: {:?}", msgs);
        
        const header_hex: &str = "11223344556677889900aabbccddeeff";
        let dst: Vec<u8> =  hex::decode("4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4d41505f4d53475f544f5f5343414c41525f41535f484153485f").unwrap();
        let header = hex::decode(header_hex).unwrap();
        let unrevealed_message_indexes = [1usize];
        let revealed_message_indexes = [0usize, 2usize];
        
        let mut rng = rand::thread_rng();
        let key_material: Vec<u8> = (0..S::Ciphersuite::IKM_LEN).map(|_| rng.gen()).collect();

        log::info!("Keypair Generation");
        let issuer_keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
            &key_material,
            None,
            None
        )?;


        let issuer_sk = issuer_keypair.private_key();
        log::info!("SK: {}", hex::encode(issuer_sk.to_bytes()));
        let issuer_pk = issuer_keypair.public_key();
        log::info!("PK: {}", hex::encode(issuer_pk.to_bytes()));

        log::info!("Computing Generators");

        // let generators = Generators::create::<S::Ciphersuite>(msgs.len());
        //Map Messages to Scalars

        let msgs_scalars: Vec<BBSplusMessage> = msgs.iter().map(|m| BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap(), Some(&dst)).unwrap()).collect();
        
        log::info!("Computing pedersen commitment on messages");
        // let commitment = Commitment::<BBSplus<S::Ciphersuite>>::commit(&msgs_scalars, None, &issuer_pk, &unrevealed_message_indexes);
        
        
        let unrevealed_msgs: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
            if unrevealed_message_indexes.contains(&i) {
                Some(*m)
            } else {
                None
            }
        }).collect();

        let revealed_msgs: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
            if !unrevealed_message_indexes.contains(&i) {
                Some(*m)
            } else {
                None
            }
        }).collect();


        //Holder receive nonce from Issuer
        let nonce_issuer = generate_nonce();
        log::info!("Generate Nonce...");
        log::info!("Nonce: {}", hex::encode(&nonce_issuer));


        log::info!("Computation of a Zero-Knowledge proof-of-knowledge of committed messages");
        // let zkpok = ZKPoK::<BBSplus<S::Ciphersuite>>::generate_proof(&unrevealed_msgs, commitment.bbsPlusCommitment(), &generators, &unrevealed_message_indexes, &nonce_issuer);


        //Issuer compute blind signature
        log::info!("Verification of the Zero-Knowledge proof and computation of a blind signature");
        // let blind_signature = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(&revealed_msgs, commitment.bbsPlusCommitment(), &zkpok, issuer_sk, issuer_pk, Some(&generators), &revealed_message_indexes, &unrevealed_message_indexes, &nonce_issuer, Some(&header));

        // if let Err(e) = &blind_signature {
        //     println!("Error: {}", e);
        // }
        
        // assert!(blind_signature.is_ok(), "Blind Signature Error");

        //Holder unblind the signature
        log::info!("Signature unblinding and verification...");
        // let unblind_signature = blind_signature.unwrap().unblind_sign(commitment.bbsPlusCommitment());

        // let verify = unblind_signature.verify(issuer_pk, Some(&msgs_scalars), Some(&header));

        // assert!(verify, "Unblinded Signature NOT VALID!");
        // log::info!("Signature is VALID!");

        //Holder receive nonce from Verifier
        let nonce_verifier = generate_nonce();
        log::info!("Generate Nonce...");
        log::info!("Nonce: {}", hex::encode(&nonce_verifier));

        // //Holder generates SPoK
        // log::info!("Computation of a Zero-Knowledge proof-of-knowledge of a signature");
        // let proof = PoKSignature::<BBSplus<S::Ciphersuite>>::proof_gen(unblind_signature.bbsPlusSignature(), &issuer_pk, Some(&msgs_scalars), Some(&generators), Some(&revealed_message_indexes), Some(&header), Some(&nonce_verifier), None);

        // //Verifier verifies SPok
        // log::info!("Signature Proof of Knowledge verification...");
        // let proof_result = proof.proof_verify(&issuer_pk, Some(&revealed_msgs), Some(&generators), Some(&revealed_message_indexes), Some(&header), Some(&nonce_verifier));
        // assert!(proof_result, "Signature Proof of Knowledge Verification Failed!");
        // log::info!("Signature Proof of Knowledge is VALID!");

        Ok(())
    }

}

#[cfg(feature = "bbsplus")]
fn main() {
    
    use std::env;
    use zkryptium::schemes::algorithms::{BBS_BLS12381_SHA256, BBS_BLS12381_SHAKE256};
    use crate::bbsplus_example::bbsplus_main;


    dotenv::dotenv().ok();
    env_logger::init();

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("Usage: {} <cipher_suite>
                Ciphersuites:
                    - BLS12-381-SHA-256
                    - BLS12-381-SHAKE-256", args[0]);
        return;
    }

    let cipher_suite = &args[1];

    match cipher_suite.as_str() {
        "BLS12-381-SHA-256" => {
            println!("\n");
            log::info!("Ciphersuite: BLS12-381-SHA-256");
            bbsplus_main::<BBS_BLS12381_SHA256>();
        }
        "BLS12-381-SHAKE-256" => {
            println!("\n");
            log::info!("Ciphersuite: BLS12-381-SHAKE-256");
            bbsplus_main::<BBS_BLS12381_SHAKE256>();

        }
        _ => {
            println!("Unknown cipher suite: {}", cipher_suite);
            // Handle other cipher suites or raise an error if necessary
        }
    }
    
}


#[cfg(not(feature = "bbsplus"))]
fn main() {}