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
    use serde::{Deserialize, Serialize};
    use serde_json::json;
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

    pub(crate) fn bbsplus_main<S: Scheme>
    ( ) -> Result<(), Error>

    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        

        const MSGS: [&str; 18] = [
        "did:web:docker%3a49000:.well-known:did_zk.json",
        "did:jwk:eyJrdHkiOiJPS1AiLCJhbGciOiJFZERTQSIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZEZpbXVrZUo5LTAwS19xaTQ5eDhZeGdKcmZJWXRsMUtkaFJZcjNhdXRMdyJ9",
        "1804772082",
        "1773149682",
        "did:web:docker%3a49000:.well-known:did_zk.json/vc/4186",
        "https://www.w3.org/2018/credentials/v1",
        "VerifiableCredential",
        "1990-09-22",
        "Master",
        "Male",
        "John",
        "Engineer",
        "Doe",
        "did:web:docker%3a49000:.well-known:did_zk.json#my-revocation-service",
        "RevocationTimeframe2024",
        "2026-03-11T13:35:42Z",
        "4186",
        "2026-03-11T13:34:42Z"
        ];

        let header_hex = json!({
            "typ": "JPT",
            "alg": "BBS-BLS12381-SHA256", 
            "kid": "did:web:docker%3a49000:.well-known:did_zk.json#pT-fdelJIrORgxXQRPIkiqJxWd7SdUSxV91pLIapK68",
            "claims": [
                "iss",
                "sub",
                "exp",
                "nbf",
                "jti",
                "vc.@context",
                "vc.type",
                "vc.credentialSubject.dateOfBirth",
                "vc.credentialSubject.educationLevel",
                "vc.credentialSubject.gender",
                "vc.credentialSubject.name",
                "vc.credentialSubject.occupation",
                "vc.credentialSubject.surname",
                "vc.credentialStatus.id",
                "vc.credentialStatus.type",
                "vc.credentialStatus.endValidityTimeframe",
                "vc.credentialStatus.revocationBitmapIndex",
                "vc.credentialStatus.startValidityTimeframe"
            ]});

      //  const HEADER_HEX: &str = "11223344556677889900aabbccddeeff";
        //let header = hex::decode(header_hex).unwrap();
        let header = header_hex.to_string().into_bytes();
        let mut rng = rand::thread_rng();
        let key_material: Vec<u8> = (0..S::Ciphersuite::IKM_LEN).map(|_| rng.gen()).collect();


        let issuer_keypair =
            KeyPair::<BBSplus<S::Ciphersuite>>::generate(&key_material, None, None)?;

        let issuer_sk = issuer_keypair.private_key();
        let issuer_pk = issuer_keypair.public_key();
        
        let messages: Vec<Vec<u8>> = MSGS.iter().map(|m| m.as_bytes().to_vec()).collect();

        let signature = Signature::<BBSplus<S::Ciphersuite>>::sign(
            Some(&messages),
            issuer_sk,
            issuer_pk,
            Some(&header),
        )
        .unwrap();

        signature.verify(issuer_pk, Some(&messages), Some(&header)).unwrap();

        //Holder receive nonce from Verifier
        let nonce_verifier = generate_random_secret(32);

        let disclosed_indexes = [1, 2,3,4,7,8,9,10,11,12,16];

        let proof = PoKSignature::<BBSplus<S::Ciphersuite>>::proof_gen(
            issuer_pk,
            &signature.to_bytes(),
            Some(&header),
            Some(&nonce_verifier),
            Some(&messages),
            Some(&disclosed_indexes),
        )
        .unwrap();

        //println!("proof sz {:?} byte", proof.to_bytes().len());

        //Verifier verifies SPok
        let disclosed_messages = get_messages_vec(&messages, &disclosed_indexes);

        let proof_result = proof
            .proof_verify(
                &issuer_pk,
                Some(&disclosed_messages),
                Some(&disclosed_indexes),
                Some(&header),
                Some(&nonce_verifier),
            )
            .is_ok();

        signature.update_signature(
            issuer_sk, 
            "2026-03-11T13:35:42Z".as_bytes(),
            "2026-04-11T13:35:42Z".as_bytes(),
            14,
            18
        ).unwrap();
        Ok(())
    }
}

#[cfg(feature = "bbsplus")]
fn main() {
    use crate::bbsplus_example::{bbsplus_main};
    use std::{collections::VecDeque, env, time::Duration};
    use zkryptium::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};

    dotenv::dotenv().ok();
    env_logger::init();

    for i in 0..110000 {
            println!("Iteration {}", i);
            let _ = bbsplus_main::<BbsBls12381Sha256>();
    }

/*     let args: Vec<String> = env::args().collect();

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
    }*/
}

#[cfg(not(feature = "bbsplus"))]
fn main() {}
