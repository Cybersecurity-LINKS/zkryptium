use std::time::Instant;

use hex::ToHex;
use links_crypto::{utils::random, keys::{cl03_key::{CL03PublicKey}, pair::{KeyPair}, bbsplus_key::{BBSplusSecretKey}}, bbsplus::{generators::{make_generators, global_generators, signer_specific_generators, print_generators}, ciphersuites::Bls12381Shake256}, schemes::algorithms::{CL03, BBSplus, Scheme}};

use links_crypto::keys::key::PrivateKey;

fn prova<S: Scheme>(keypair: &KeyPair<S>){
    let sk = keypair.private_key();

    println!("SK: {}", sk.encode());

    
}

fn main() {

    const IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";

    let write_data_start_time = Instant::now();
    
    let cl03_keypair = KeyPair::<CL03>::generate();
    let bbsplus_keypair = KeyPair::<BBSplus>::generate(
        &hex::decode(&IKM).unwrap(),
        Some(&hex::decode(&KEY_INFO).unwrap())
    );

    println!("BBS+ KeyPair = {:?}", bbsplus_keypair);
    println!("SK: {}", bbsplus_keypair.private_key().encode());
    println!("PK: {}", bbsplus_keypair.public_key().encode());

    println!("Create Key {:.2?}", write_data_start_time.elapsed());

    println!("CL03 KeyPair = {:?}", cl03_keypair);


    // Suite specific create generators function
    let get_generators_fn = make_generators::<Bls12381Shake256>;

    let generators = global_generators(get_generators_fn, 5);
    let generators2 = signer_specific_generators(get_generators_fn, 5);

    print_generators(&generators);

    prova(&bbsplus_keypair);

    bbsplus_keypair.write_keypair_to_file(Some("keypair.txt".to_string()));

}