use std::fs;

use bbsplus::ciphersuites::BbsCiphersuite;
use elliptic_curve::{hash2curve::ExpandMsg, group::Curve};
use schemes::algorithms::Scheme;

use crate::{bbsplus::{message::{BBSplusMessage, Message}, self, generators::{make_generators, global_generators, print_generators}}, schemes};



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
    println!("{}", result["caseName"]);
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

    assert!(boolean, "{}", true);
}


pub(crate) fn message_generators<S: Scheme>(filename: &str) 
where
    S::Ciphersuite: BbsCiphersuite,
    <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
{
    let data = fs::read_to_string(filename).expect("Unable to read file");
    let result: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
    println!("Message Generators");

    let get_generators_fn = make_generators::<S::Ciphersuite>;
    let generators = global_generators(get_generators_fn, 1);
    // print_generators(&generators);

    let expected_BP = result["BP"].as_str().unwrap();
    // println!("{}", BP);

    let BP = hex::encode(generators.g1_base_point.to_affine().to_compressed());

    let result = BP == expected_BP;
    // println!("{}", result);

    if result == false {
        println!("{}", result);
        println!("  GENERATOR BP: {}", result);
        println!("  Expected: {}", expected_BP);
        println!("  Computed: {}", BP);
    }



}