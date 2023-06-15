use std::fs;

use bbsplus::ciphersuites::BbsCiphersuite;
use elliptic_curve::{hash2curve::ExpandMsg, group::Curve};
use schemes::algorithms::Scheme;

use crate::{bbsplus::{message::{BBSplusMessage, Message}, self, generators::{make_generators, global_generators, print_generators}}, schemes::{self, algorithms::BBSplus}, signatures::signature::{BBSplusSignature, Signature}, keys::bbsplus_key::{BBSplusSecretKey, BBSplusPublicKey}, utils::util::{hash_to_scalar_old, ScalarExt}};



pub(crate) fn map_message_to_scalar_as_hash<S: Scheme>(filename: &str) 
where
    S::Ciphersuite: BbsCiphersuite,
    <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
{
    let path_messages = "./fixture_data/messages.json";
    let data = fs::read_to_string(path_messages).expect("Unable to read file");
    let messages: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    // println!("{}", messages);

    // let filename = "./fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json";
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let result: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    eprintln!("{}", result["caseName"]);
    // println!("{}", result["dst"].as_str().unwrap());
    let dst = hex::decode(result["dst"].as_str().unwrap()).unwrap();
    let cases = result["cases"].as_array().unwrap();

    let mut boolean = true;
    let mut idx = 0usize;
    for m in messages.as_array().unwrap() {
        let msg = &cases[idx]["message"];
        assert_eq!(m, msg);

        let msg_hex = hex::decode(msg.as_str().unwrap()).unwrap();

        let out = hex::encode(BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&msg_hex, Some(&dst)).to_bytes_be());
        let out_expected = cases[idx]["scalar"].as_str().unwrap();

        if out != out_expected{
            boolean = false;
        };

        idx += 1;
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

    let get_generators_fn = make_generators::<S::Ciphersuite>;
    let generators = global_generators(get_generators_fn, generators_expected.len() + 2);
    // print_generators(&generators);

    let expected_BP = res["BP"].as_str().unwrap();
    // println!("{}", BP);

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
    let Q1 = hex::encode(generators.q1.to_affine().to_compressed());

    if expected_Q1 != Q1 {
        result = false;
        eprintln!("  GENERATOR Q1: {}", result);
        eprintln!("  Expected: {}", expected_Q1);
        eprintln!("  Computed: {}", Q1);
    }


    let expected_Q2 = res["Q2"].as_str().unwrap();
    let Q2 = hex::encode(generators.q2.to_affine().to_compressed());

    if expected_Q2 != Q2 {
        result = false;
        eprintln!("  GENERATOR Q2: {}", result);
        eprintln!("  Expected: {}", expected_Q2);
        eprintln!("  Computed: {}", Q2);
    }


    generators_expected.iter().enumerate().for_each(|(i, expected_g)| {
        let g = hex::encode(generators.message_generators.get(i).expect("index overflow").to_affine().to_compressed());
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
    let msgs_hex: Vec<&str> = res["messages"].as_array().unwrap().iter().map(|m| m.as_str().unwrap()).collect();
    let SK_hex = res["signerKeyPair"]["secretKey"].as_str().unwrap();
    let PK_hex = res["signerKeyPair"]["publicKey"].as_str().unwrap();
    let SIGNATURE_expected = res["signature"].as_str().unwrap();
    let RESULT_expected = res["result"]["valid"].as_bool().unwrap();

    let header = hex::decode(header_hex).unwrap();
    let SK = BBSplusSecretKey::from_bytes(&hex::decode(SK_hex).unwrap());
    let PK = BBSplusPublicKey::from_bytes(&hex::decode(PK_hex).unwrap());


    //Map Messages to Scalars
    let data = fs::read_to_string([pathname, "MapMessageToScalarAsHash.json"].concat()).expect("Unable to read file");
    let msg_scalars: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");

    let dst = hex::decode(msg_scalars["dst"].as_str().unwrap()).unwrap();

    let msg_scalars: Vec<BBSplusMessage> = msgs_hex.iter().map(|m| BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap(), Some(&dst))).collect();
    
    //Precompute generators 
    let get_generators_fn = make_generators::<S::Ciphersuite>;
    let generators = global_generators(get_generators_fn, msg_scalars.len() + 2);

    //Sign the message
    let signature = Signature::<BBSplus<S::Ciphersuite>>::sign(Some(&msg_scalars), &SK, &PK, &generators, Some(&header));

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
    let result2 = signature_expected.verify(&PK, Some(&msg_scalars), &generators, Some(&header));
    let result3 = result2 == RESULT_expected;

    if !result3 {
        eprintln!("  VERIFY: {}", result3);
        eprintln!("  Expected: {}", RESULT_expected);
        eprintln!("  Computed: {}", result2);
        assert!(result3, "failed");
       
    } 

    eprintln!("  SIGN: {}", result1);
    eprintln!("  Expected: {}", SIGNATURE_expected);
    eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));

    eprintln!("  VERIFY: {}", result3);
    eprintln!("  Expected: {}", RESULT_expected);
    eprintln!("  Computed: {}", result2);
    eprintln!("{} ({})", result3, res["result"]["reason"].as_str().unwrap());
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
    let count = usize::try_from(res["count"].as_u64().unwrap()).unwrap();
    let scalars_hex = res["scalars"].as_array().unwrap();

    let msg = hex::decode(msg_hex).unwrap();
    let dst = hex::decode(dst_hex).unwrap();

    assert_eq!(count, scalars_hex.len(), "count != len(SCALARS_hex)");

    let scalars = hash_to_scalar_old::<S::Ciphersuite>(&msg, count, Some(&dst));

    let mut results = true;

    for i in 0..count {
        let scalar_hex = hex::encode(scalars[i].to_bytes_be());
        let scalar_expected = scalars_hex[i].as_str().unwrap();

        if scalar_hex != scalar_expected {
            if results {
                results = false;
                eprintln!("{}", results);
            }

            eprintln!(" count: {}", i);
            eprintln!(" Expected scalar: {}", scalar_expected);
            eprintln!(" Computed scalar: {}", scalar_hex);
        }

    }

    assert!(results, "Failed");
}