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

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

#[cfg(feature = "bbsplus")]
#[cfg(test)]
mod bbsplus_tests {
    
    use std::fs;
    use bbsplus::ciphersuites::BbsCiphersuite;
    use elliptic_curve::{hash2curve::ExpandMsg, group::Curve};
    use schemes::algorithms::Scheme;
    use zkryptium::{bbsplus::{self, generators::Generators, keys::{BBSplusPublicKey, BBSplusSecretKey}}, keys::pair::KeyPair, schemes::{self, algorithms::BBSplus, generics::Signature}, utils::{message::BBSplusMessage, util::bbsplus_utils::{hash_to_scalar, ScalarExt}}};
    use zkryptium::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
    
    
    
    //KEYPAIR - SHA256
    
    #[test]
    fn keypair_sha256() { //UPDATED!
        key_pair_gen::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/keyPair.json");
    }

    //KEYPAIR - SHAKE256

    #[test]
    fn keypair_shake256() { //UPDATED!
        key_pair_gen::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/keyPair.json");
    }


    //MAP MESSAGE TO SCALAR - SHA256

    #[test]
    fn map_message_to_scalar_as_hash_sha256() { //UPDATED!
        map_message_to_scalar_as_hash::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json");
    }

    //MAP MESSAGE TO SCALAR - SHAKE256

    #[test]
    fn map_message_to_scalar_as_hash_shake256() {//UPDATED!
        map_message_to_scalar_as_hash::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/MapMessageToScalarAsHash.json");
    }


    //GENERATORS - SHA256
    #[test]
    fn message_generators_sha256() { //UPDATED
        message_generators::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/generators.json");
    }

    //GENERATORS - SHAKE256

    #[test]
    fn message_generators_shake256() { //UPDATED
        message_generators::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/generators.json");
    }


    //MSG SIGNATURE - UPDATED
    #[test]
    fn msg_signature_sha256_1() {
        msg_signature::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "signature/signature001.json");
    }
    #[test]
    fn msg_signature_sha256_2() {
        msg_signature::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "signature/signature002.json");
    }
    #[test]
    fn msg_signature_sha256_3() {
        msg_signature::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "signature/signature003.json");
    }
    #[test]
    fn msg_signature_sha256_4() {
        msg_signature::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json");
    }
    #[test]
    fn msg_signature_sha256_5() {
        msg_signature::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "signature/signature005.json");
    }
    #[test]
    fn msg_signature_sha256_6() {
        msg_signature::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "signature/signature006.json");
    }
    #[test]
    fn msg_signature_sha256_7() {
        msg_signature::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "signature/signature007.json");
    }
    #[test]
    fn msg_signature_sha256_8() {
        msg_signature::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "signature/signature008.json");
    }
    #[test]
    fn msg_signature_sha256_9() {
        msg_signature::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "signature/signature009.json");
    }


    //MSG SIGNATURE - SHAKE256 - UPDATED
    #[test]
    fn msg_signature_shake256_1() {
        msg_signature::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "signature/signature001.json");
    }
    #[test]
    fn msg_signature_shake256_2() {
        msg_signature::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "signature/signature002.json");
    }
    #[test]
    fn msg_signature_shake256_3() {
        msg_signature::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "signature/signature003.json");
    }
    #[test]
    fn msg_signature_shake256_4() {
        msg_signature::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json");
    }
    #[test]
    fn msg_signature_shake256_5() {
        msg_signature::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "signature/signature005.json");
    }
    #[test]
    fn msg_signature_shake256_6() {
        msg_signature::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "signature/signature006.json");
    }
    #[test]
    fn msg_signature_shake256_7() {
        msg_signature::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "signature/signature007.json");
    }
    #[test]
    fn msg_signature_shake256_8() {
        msg_signature::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "signature/signature008.json");
    }
    #[test]
    fn msg_signature_shake256_9() {
        msg_signature::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "signature/signature009.json");
    }

    //h2s - SHA256 - UPDATED
    #[test]
    fn h2s_sha256_1() {
        h2s::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "h2s.json");
    }
    #[test]
    fn h2s_sha256_2() {
        h2s::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "h2s.json");
    }

    //h2s - SHAKE256 -> UPDATED
    #[test]
    fn h2s_shake256_1() {
        h2s::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "h2s.json");
    }
    #[test]
    fn h2s_shake256_2() {
        h2s::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "h2s.json");
    }


    // //Update Blinded Signature - SHA256
    // #[test]
    // fn update_blind_signature_sha256() {
    //     update_blind_signature::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/");
    // }

    // //Update Blinded Signature - SHAKE256
    // #[test]
    // fn update_blind_signature_shake256() {
    //     update_blind_signature::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/");
    // }


    // //Update Signature - SHA256
    // #[test]
    // fn update_signature_sha256() {
    //     update_signature::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/");
    // }

    // //Update Blinded Signature - SHAKE256
    // #[test]
    // fn update_signature_shake256() {
    //     update_signature::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/");
    // }


    pub(crate) fn key_pair_gen<S: Scheme>(filename: &str) 
    where
        S::Ciphersuite: BbsCiphersuite
    {
        eprintln!("Key Pair");
        let data = fs::read_to_string(filename).expect("Unable to read file");
        let data_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        let IKM         = data_json["keyMaterial"].as_str().unwrap();
        let KEY_INFO    = data_json["keyInfo"].as_str().unwrap();
        let KEY_DST = data_json["keyDst"].as_str().unwrap();
        let SK_expected = data_json["keyPair"]["secretKey"].as_str().unwrap();                  
        let PK_expected = data_json["keyPair"]["publicKey"].as_str().unwrap();  

        let keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
            &hex::decode(IKM).unwrap(), 
            Some(&hex::decode(KEY_INFO).unwrap()), 
            Some(&hex::decode(KEY_DST).unwrap())
        ).unwrap();
        
        let sk = keypair.private_key().encode();
        let pk = keypair.public_key().encode();

        let result1 = sk == SK_expected;

        if result1 == false{
        println!("      keyGen:        {}", result1);
        println!("      Expected key:  {}", SK_expected);
        println!("      Generated key: {}", sk);
        }

        let result2 = pk ==  PK_expected;

        if result2 == false{
            println!("      skToPk:        {}", result2);
            println!("      Expected key:  {}", PK_expected);
            println!("      Generated key: {}", pk);
            }
        let result = result1 && result2;

        assert!(result, "Failed");

    }

    pub(crate) fn map_message_to_scalar_as_hash<S: Scheme>(filename: &str) 
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        // let path_messages = "./fixture_data/messages.json";
        // let data = fs::read_to_string(path_messages).expect("Unable to read file");
        // let messages: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        // // println!("{}", messages);

        // let filename = "./fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json";
        let data = fs::read_to_string(filename).expect("Unable to read file");
        let json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        eprintln!("{}", json["caseName"]);
        let cases = json["cases"].as_array().unwrap();

        let mut boolean = true;
        for c in cases {
            let msg = &c["message"];

            let msg_hex = hex::decode(msg.as_str().unwrap()).unwrap();

            let out = hex::encode(BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&msg_hex, <S::Ciphersuite as BbsCiphersuite>::API_ID).unwrap().to_bytes_be());
            let out_expected = c["scalar"].as_str().unwrap();

            if out != out_expected{
                boolean = false;
            };
        }

        assert_eq!(boolean, true);
    }


    pub(crate) fn message_generators<S: Scheme>(filename: &str) 
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string(filename).expect("Unable to read file");
        let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        eprintln!("Message Generators");

        let mut generators_expected: Vec<&str> = Vec::new();
        for g in res["MsgGenerators"].as_array().unwrap() {
            generators_expected.push(g.as_str().unwrap());
        }

        println!("{}", generators_expected.len());
        let generators = Generators::create::<S::Ciphersuite>(generators_expected.len() + 1, Some(<S::Ciphersuite as BbsCiphersuite>::API_ID));
        println!("{}", generators.values.len());

        let Q1 = generators.values[0];
        let message_generators = &generators.values[1..];

        let expected_BP = res["P1"].as_str().unwrap();

        //check BP
        let BP = hex::encode(generators.g1_base_point.to_affine().to_compressed());

        let mut result = BP == expected_BP;
        // println!("{}", result);

        if result == false {
            eprintln!("{}", result);
            eprintln!("  GENERATOR BP: {}", result);
            eprintln!("  Expected: {}", expected_BP);
            eprintln!("  Computed: {}", BP);
        }

        let expected_Q1 = res["Q1"].as_str().unwrap();
        let Q1 = hex::encode(Q1.to_compressed());

        if expected_Q1 != Q1 {
            result = false;
            eprintln!("  GENERATOR Q1: {}", result);
            eprintln!("  Expected: {}", expected_Q1);
            eprintln!("  Computed: {}", Q1);
        }


        generators_expected.iter().enumerate().for_each(|(i, expected_g)| {
            let g = hex::encode(message_generators.get(i).expect("index overflow").to_affine().to_compressed());
            if *expected_g != g{
                result = false;
                eprintln!("  GENERATOR {}: {}", i, result);
                eprintln!("  Expected: {}", *expected_g);
                eprintln!("  Computed: {}", g);
            }
        });


        assert_eq!(result, true);

    }


    pub(crate) fn msg_signature<S: Scheme>(pathname: &str, filename: &str) 
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
        let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        eprintln!("{}", res["caseName"]);

        let header_hex = res["header"].as_str().unwrap();
        let msgs_hex: Vec<String> = res["messages"].as_array().unwrap().iter().map(|m| serde_json::from_value(m.clone()).unwrap()).collect();
        let SK_hex = res["signerKeyPair"]["secretKey"].as_str().unwrap();
        let PK_hex = res["signerKeyPair"]["publicKey"].as_str().unwrap();
        let SIGNATURE_expected = res["signature"].as_str().unwrap();
        let RESULT_expected = res["result"]["valid"].as_bool().unwrap();

        let header = hex::decode(header_hex).unwrap();
        let SK = BBSplusSecretKey::from_bytes(&hex::decode(SK_hex).unwrap()).unwrap();
        let PK = BBSplusPublicKey::from_bytes(&hex::decode(PK_hex).unwrap()).unwrap();

        let messages: Vec<Vec<u8>> = msgs_hex.iter().map(|m| hex::decode(m).unwrap()).collect();

        let signature = Signature::<BBSplus<S::Ciphersuite>>::sign(Some(&messages), &SK, &PK, Some(&header)).unwrap();

        let result0 = hex::encode(signature.to_bytes()) == SIGNATURE_expected;

        let result1 = result0 == RESULT_expected;
        if !result1 {
            eprintln!("  SIGN: {}", result1);
            eprintln!("  Expected: {}", SIGNATURE_expected);
            eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));
            assert!(result1, "failed")
        }



        //Verify the signature

        let signature_expected = Signature::<BBSplus<S::Ciphersuite>>::from_bytes(&hex::decode(SIGNATURE_expected).unwrap().try_into().unwrap()).unwrap();
        let result2 = signature_expected.verify(&PK, Some(&messages),  Some(&header)).is_ok();
        let result3 = result2 == RESULT_expected;

        if !result3 {
            eprintln!("  VERIFY: {}", result3);
            eprintln!("  Expected: {}", RESULT_expected);
            eprintln!("  Computed: {}", result2);
            assert!(result3, "failed");
        
        }else {
            eprintln!("  SIGN: {}", result1);
            eprintln!("  Expected: {}", SIGNATURE_expected);
            eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));
        
            eprintln!("  VERIFY: {}", result3);
            eprintln!("  Expected: {}", RESULT_expected);
            eprintln!("  Computed: {}", result2);
            if RESULT_expected == false {
                eprintln!("{} ({})", result3, res["result"]["reason"].as_str().unwrap());
            }
        }

    }


    pub(crate) fn h2s<S: Scheme>(pathname: &str, filename: &str) 
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
        let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        eprintln!("{}", res["caseName"]);

        let msg_hex = res["message"].as_str().unwrap();
        let dst_hex = res["dst"].as_str().unwrap();
        let scalar_hex_expected = res["scalar"].as_str().unwrap();

        let msg = hex::decode(msg_hex).unwrap();
        let dst = hex::decode(dst_hex).unwrap();


        let scalar = hash_to_scalar::<S::Ciphersuite>(&msg, &dst).unwrap();

        let mut result = true;

        let scalar_hex = hex::encode(scalar.to_bytes_be());

        if scalar_hex != scalar_hex_expected {
            result = false;
            eprintln!("{}", result);

            eprintln!(" Expected scalar: {}", scalar_hex_expected);
            eprintln!(" Computed scalar: {}", scalar_hex);
        }

        assert!(result, "Failed");
    }


    // pub(crate) fn blind_messages_proof_gen<S: Scheme>(pathname: &str) 
    // where
    //     S::Ciphersuite: BbsCiphersuite,
    //     <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    // {
    //     const IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    //     const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";
    //     const msgs: [&str; 3] = ["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6", "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"];
    //     const msgs_wrong: [&str; 3] = ["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac7", "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b91"];
    //     let unrevealed_message_indexes = [1usize];
    //     // let nonce = generate_nonce();
    //     let nonce = b"aaaa".as_slice();

    //     let keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
    //         &hex::decode(&IKM).unwrap(),
    //         Some(&hex::decode(&KEY_INFO).unwrap()),
    //         None
    //     ).unwrap();

    //     let pk = keypair.public_key();

    //     let generators = Generators::create::<S::Ciphersuite>(msgs.len(), Some(<S::Ciphersuite as BbsCiphersuite>::API_ID));

    //     //Map Messages to Scalars
    //     let data_scalars = fs::read_to_string([pathname, "MapMessageToScalarAsHash.json"].concat()).expect("Unable to read file");
    //     let scalars_json: serde_json::Value = serde_json::from_str(&data_scalars).expect("Unable to parse");
    //     let dst = hex::decode(scalars_json["dst"].as_str().unwrap()).unwrap();

    //     let msgs_scalars: Vec<BBSplusMessage> = msgs.iter().map(|m| BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap(), Some(&dst)).unwrap()).collect();
    //     let msgs_scalars_wrong: Vec<BBSplusMessage> = msgs_wrong.iter().map(|m| BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap(), Some(&dst)).unwrap()).collect();

    //     let commitment = Commitment::<BBSplus<S::Ciphersuite>>::commit(&msgs_scalars, Some(&generators), &pk, &unrevealed_message_indexes);
    //     let commitment_wrong = Commitment::<BBSplus<S::Ciphersuite>>::commit(&msgs_scalars_wrong, Some(&generators), &pk, &unrevealed_message_indexes);

        
    //     let unrevealed_msgs: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
    //         if unrevealed_message_indexes.contains(&i) {
    //             Some(*m)
    //         } else {
    //             None
    //         }
    //     }).collect();

    //     let unrevealed_msgs_wrong: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
    //         if unrevealed_message_indexes.contains(&i) {
    //             Some(*m)
    //         } else {
    //             None
    //         }
    //     }).collect();

    //     let zkpok = ZKPoK::<BBSplus<S::Ciphersuite>>::generate_proof(&unrevealed_msgs, commitment.bbsPlusCommitment(), &generators, &unrevealed_message_indexes, &nonce);
    //     let verify = zkpok.verify_proof(commitment.bbsPlusCommitment(), &generators, &unrevealed_message_indexes, nonce);

    //     assert!(verify, "Error! Verification should PASS");

    //     let wrong_zkpok = ZKPoK::<BBSplus<S::Ciphersuite>>::generate_proof(&unrevealed_msgs_wrong, commitment_wrong.bbsPlusCommitment(), &generators, &unrevealed_message_indexes, &nonce);
    //     let verify = wrong_zkpok.verify_proof(commitment.bbsPlusCommitment(), &generators, &unrevealed_message_indexes, nonce);

    //     assert!(!verify, "Error! Verification should FAIL");


        
    // }

    // pub(crate) fn blind_sign<S: Scheme>(pathname: &str) 
    // where
    //     S::Ciphersuite: BbsCiphersuite,
    //     <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    // {
    //     const IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    //     const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";
    //     const msgs: [&str; 3] = ["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6", "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"];
    //     const msgs_wrong: [&str; 3] = ["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac7", "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b91"];
    //     const header_hex: &str = "11223344556677889900aabbccddeeff";
    //     let header = hex::decode(header_hex).unwrap();
    //     let unrevealed_message_indexes = [1usize];
    //     let revealed_message_indexes = [0usize, 2usize];
    //     // let nonce = generate_nonce();
    //     let nonce = b"aaaa".as_slice();

    //     let messages: Vec<Vec<u8>> = msgs.iter().map(|m| {
    //         hex::decode(m).unwrap().into()
    //     }).collect();

    //     let messages_wrong: Vec<Vec<u8>> = msgs_wrong.iter().map(|m| {
    //         hex::decode(m).unwrap().into()
    //     }).collect();

    //     let keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
    //         &hex::decode(&IKM).unwrap(),
    //         Some(&hex::decode(&KEY_INFO).unwrap()),
    //         None
    //     ).unwrap();

    //     let sk = keypair.private_key();
    //     let pk = keypair.public_key();

    //     let generators = Generators::create::<S::Ciphersuite>(msgs.len());

    //     //Map Messages to Scalars
    //     let data_scalars = fs::read_to_string([pathname, "MapMessageToScalarAsHash.json"].concat()).expect("Unable to read file");
    //     let scalars_json: serde_json::Value = serde_json::from_str(&data_scalars).expect("Unable to parse");
    //     let dst = hex::decode(scalars_json["dst"].as_str().unwrap()).unwrap();

    //     let msgs_scalars: Vec<BBSplusMessage> = msgs.iter().map(|m| BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap(), Some(&dst)).unwrap()).collect();
    //     let msgs_scalars_wrong: Vec<BBSplusMessage> = msgs_wrong.iter().map(|m| BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap(), Some(&dst)).unwrap()).collect();

    //     let commitment = Commitment::<BBSplus<S::Ciphersuite>>::commit(&msgs_scalars, Some(&generators), pk, &unrevealed_message_indexes);
    //     let commitment_wrong = Commitment::<BBSplus<S::Ciphersuite>>::commit(&msgs_scalars_wrong, Some(&generators), pk, &unrevealed_message_indexes);

        
    //     let unrevealed_msgs: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
    //         if unrevealed_message_indexes.contains(&i) {
    //             Some(*m)
    //         } else {
    //             None
    //         }
    //     }).collect();

    //     let revealed_msgs: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
    //         if !unrevealed_message_indexes.contains(&i) {
    //             Some(*m)
    //         } else {
    //             None
    //         }
    //     }).collect();

    //     let unrevealed_msgs_wrong: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
    //         if unrevealed_message_indexes.contains(&i) {
    //             Some(*m)
    //         } else {
    //             None
    //         }
    //     }).collect();

    //     let revealed_msgs_wrong: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
    //         if !unrevealed_message_indexes.contains(&i) {
    //             Some(*m)
    //         } else {
    //             None
    //         }
    //     }).collect();

    //     let zkpok = ZKPoK::<BBSplus<S::Ciphersuite>>::generate_proof(&unrevealed_msgs, commitment.bbsPlusCommitment(), &generators, &unrevealed_message_indexes, &nonce);

    //     let blind_signature = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(&revealed_msgs, commitment.bbsPlusCommitment(), &zkpok, sk, pk, Some(&generators), &revealed_message_indexes, &unrevealed_message_indexes, &nonce, Some(&header));

    //     if let Err(e) = &blind_signature {
    //         println!("Error: {}", e);
    //     }
        
    //     assert!(blind_signature.is_ok(), "Blind Signature Error");

    //     let wrong_zkpok = ZKPoK::<BBSplus<S::Ciphersuite>>::generate_proof(&unrevealed_msgs_wrong, commitment_wrong.bbsPlusCommitment(), &generators, &unrevealed_message_indexes, &nonce);
    //     let blind_signature_wrong = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(&revealed_msgs, commitment.bbsPlusCommitment(), &wrong_zkpok, sk, pk, Some(&generators), &revealed_message_indexes, &unrevealed_message_indexes, &nonce, Some(&header));
        
    //     assert!(blind_signature_wrong.is_err(), "Blind Signature generation MUST fail");

    //     let unblind_signature = blind_signature.unwrap().unblind_sign(commitment.bbsPlusCommitment());

    //     let verify = unblind_signature.verify(pk, Some(&messages), Some(&header)).is_ok();

    //     assert!(verify, "Unblinded Signature NOT VALID!");

    //     let verify_wrong = unblind_signature.verify(pk, Some(&messages_wrong), Some(&header)).is_ok();

    //     assert!(!verify_wrong, "Unblinded Signature MUST be INVALID!");


    // }



    // pub(crate) fn update_blind_signature<S: Scheme>(pathname: &str)
    // where
    //     S::Ciphersuite: BbsCiphersuite,
    //     <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    // {
    //     const IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    //     const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";
    //     const msgs: [&str; 3] = ["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6", "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"];
    //     const header_hex: &str = "11223344556677889900aabbccddeeff";
    //     let header = hex::decode(header_hex).unwrap();
    //     let unrevealed_message_indexes = [1usize];
    //     let revealed_message_indexes = [0usize, 2usize];
    //     // let nonce = generate_nonce();
    //     let nonce = b"aaaa".as_slice();

    //     let messages: Vec<Vec<u8>> = msgs.iter().map(|m| {
    //         hex::decode(m).unwrap().into()
    //     }).collect();

    //     let keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
    //         &hex::decode(&IKM).unwrap(),
    //         Some(&hex::decode(&KEY_INFO).unwrap()),
    //         None
    //     ).unwrap();

    //     let sk = keypair.private_key();
    //     let pk = keypair.public_key();

    //     let generators = Generators::create::<S::Ciphersuite>(msgs.len());

    //     //Map Messages to Scalars
    //     let data_scalars = fs::read_to_string([pathname, "MapMessageToScalarAsHash.json"].concat()).expect("Unable to read file");
    //     let scalars_json: serde_json::Value = serde_json::from_str(&data_scalars).expect("Unable to parse");
    //     let dst = hex::decode(scalars_json["dst"].as_str().unwrap()).unwrap();

    //     let msgs_scalars: Vec<BBSplusMessage> = msgs.iter().map(|m| BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap(), Some(&dst)).unwrap()).collect();
        
    //     let commitment = Commitment::<BBSplus<S::Ciphersuite>>::commit(&msgs_scalars, Some(&generators), pk, &unrevealed_message_indexes);
        
        
    //     let unrevealed_msgs: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
    //         if unrevealed_message_indexes.contains(&i) {
    //             Some(*m)
    //         } else {
    //             None
    //         }
    //     }).collect();

    //     let revealed_msgs: Vec<BBSplusMessage> = msgs_scalars.iter().enumerate().filter_map(|(i, m)| {
    //         if !unrevealed_message_indexes.contains(&i) {
    //             Some(*m)
    //         } else {
    //             None
    //         }
    //     }).collect();

    //     let zkpok = ZKPoK::<BBSplus<S::Ciphersuite>>::generate_proof(&unrevealed_msgs, commitment.bbsPlusCommitment(), &generators, &unrevealed_message_indexes, &nonce);

    //     let blind_signature_result = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(&revealed_msgs, commitment.bbsPlusCommitment(), &zkpok, sk, pk, Some(&generators), &revealed_message_indexes, &unrevealed_message_indexes, &nonce, Some(&header));

    //     if let Err(e) = &blind_signature_result {
    //         println!("Error: {}", e);
    //     }
        
    //     assert!(blind_signature_result.is_ok(), "Blind Signature Error");
    //     let blind_signature = blind_signature_result.unwrap();

    //     let unblind_signature = blind_signature.unblind_sign(commitment.bbsPlusCommitment());

    //     let verify = unblind_signature.verify(pk, Some(&messages), Some(&header)).is_ok();

    //     assert!(verify, "Unblinded Signature NOT VALID!");


    //     const new_message: &str = "8872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    //     const update_index: usize = 0usize;
    //     let new_message_scalar = BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(new_message).unwrap(), Some(&dst)).unwrap();
    //     let old_message_scalar = msgs_scalars.get(update_index).unwrap();

    //     let mut new_msgs_scalars = msgs_scalars.clone();
    //     new_msgs_scalars[update_index] = new_message_scalar;

    //     let updated_signature = blind_signature.update_signature(sk, &generators, &old_message_scalar, &new_message_scalar, update_index);
    //     let unblind_updated_signature: Signature<BBSplus<<S as Scheme>::Ciphersuite>> = Signature::BBSplus(BBSplusSignature { a: updated_signature.a(), e: unblind_signature.e(), s: unblind_signature.s()});
    //     let verify = unblind_updated_signature.verify(pk, Some(&new_msgs_scalars), Some(&generators), Some(&header));

    //     assert!(verify, "Unblinded Signature NOT VALID!");

    // }


    // pub(crate) fn update_signature<S: Scheme>(pathname: &str)
    // where
    //     S::Ciphersuite: BbsCiphersuite,
    //     <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    // {
    //     const IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    //     const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";
    //     const msgs: [&str; 3] = ["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6", "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90"];
    //     const header_hex: &str = "11223344556677889900aabbccddeeff";
    //     let header = hex::decode(header_hex).unwrap();

    //     let keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
    //         &hex::decode(&IKM).unwrap(),
    //         Some(&hex::decode(&KEY_INFO).unwrap()),
    //         None
    //     ).unwrap();

    //     let sk = keypair.private_key();
    //     let pk = keypair.public_key();

    //     let generators = Generators::create::<S::Ciphersuite>(msgs.len());

    //     //Map Messages to Scalars
    //     let data_scalars = fs::read_to_string([pathname, "MapMessageToScalarAsHash.json"].concat()).expect("Unable to read file");
    //     let scalars_json: serde_json::Value = serde_json::from_str(&data_scalars).expect("Unable to parse");
    //     let dst = hex::decode(scalars_json["dst"].as_str().unwrap()).unwrap();

    //     let msgs_scalars: Vec<BBSplusMessage> = msgs.iter().map(|m| BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap(), Some(&dst)).unwrap()).collect();
        

    //     let signature = Signature::<BBSplus<S::Ciphersuite>>::sign(Some(&msgs_scalars), sk, pk, Some(&generators), Some(&header));


    //     let verify = signature.verify(pk, Some(&msgs_scalars), Some(&generators), Some(&header));

    //     assert!(verify, "Signature NOT VALID!");


    //     const new_message: &str = "8872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    //     const update_index: usize = 0usize;
    //     let new_message_scalar = BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(new_message).unwrap(), Some(&dst)).unwrap();
    //     let old_message_scalar = msgs_scalars.get(update_index).unwrap();

    //     let updated_signature = signature.update_signature(sk, &generators, &old_message_scalar, &new_message_scalar, update_index);

    //     let mut new_msgs_scalars = msgs_scalars.clone();
    //     new_msgs_scalars[update_index] = new_message_scalar;

    //     let verify = updated_signature.verify(pk, Some(&new_msgs_scalars), Some(&generators), Some(&header));

    //     assert!(verify, "Signature NOT VALID!");

    // }
}

