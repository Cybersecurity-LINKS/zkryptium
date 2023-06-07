use std::time::Instant;

use bls12_381_plus::{G1Affine, G2Affine, pairing, G1Projective, Scalar};
use byteorder::BigEndian;
use glass_pumpkin::prime::new;
use hex::ToHex;
use links_crypto::{utils::random, keys::{cl03_key::{CL03PublicKey}, pair::{KeyPair}, bbsplus_key::{BBSplusSecretKey, BBSplusPublicKey}}, bbsplus::{generators::{make_generators, global_generators, signer_specific_generators, print_generators}, ciphersuites::{Bls12381Shake256, BbsCiphersuite, Bls12381Sha256}, message::{Message, BBSplusMessage, CL03Message}}, schemes::algorithms::{CL03, BBSplus, Scheme, CL03Sha256, BBSplusShake256, BBSplusSha256}, signatures::{commitment::{Commitment, BBSplusCommitment, self}, blind::{self, BlindSignature, BBSplusBlindSignature}, signature::{BBSplusSignature, Signature}, proof::PoKSignature}, cl03::ciphersuites::CLSha256};

use links_crypto::keys::key::PrivateKey;
use rug::Integer;

fn prova<S: Scheme>(keypair: &KeyPair<S>)
where
    S: Scheme<PrivKey = BBSplusSecretKey, PubKey = BBSplusPublicKey>
{
    let sk = keypair.private_key();

    println!("SK: {}", sk.encode());
}

fn prova2<CS: BbsCiphersuite>(commitment: Commitment<BBSplus<CS>>)
{
    
    let value = commitment.value();
    let randomness = commitment.randomness();
    println!("commitment: {:?}", value);
    println!("randomness: {:?}", randomness);

}

//b*x = a mod m
fn divm(a: Integer, b: Integer, m: Integer) -> Integer{
    let mut num = a.clone();
    let mut den = b.clone();
    let mut module = m.clone();
    let mut r: Integer;
    let mut result = b.invert_ref(&m);
    let mut ok = result.is_none();
    if ok {
        let mut gcd = Integer::from(a.gcd_ref(&b));
        gcd.gcd_mut(&m);
        num = Integer::from(a.div_exact_ref(&gcd));
        den = Integer::from(b.div_exact_ref(&gcd));
        module = Integer::from(m.div_exact_ref(&gcd));
        result = den.invert_ref(&module);
        ok = result.is_none();
    }

    if !ok {
        r = Integer::from(result.unwrap());
        let z = (r * num) % module;
        z
    } else {
        panic!("No solution");
    }

}

fn prova3<CS: BbsCiphersuite>(signature: BlindSignature<BBSplus<CS>>)
{
    let a = signature.a();


    println!("{:?}", a);
}

fn test_bbsplus_sign() {

    const IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";



    const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    // const msg: &str = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80";
    const msg_wrong: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03";
    const dst: &str = "4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4d41505f4d53475f544f5f5343414c41525f41535f484153485f";
    const dst_sha256: &str = "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4d41505f4d53475f544f5f5343414c41525f41535f484153485f";
    const header:&str = "11223344556677889900aabbccddeeff";
    const ph: &str = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501";
    let revealed_message_indexes = [0usize];
    const seed: &str = "332e313431353932363533353839373933323338343632363433333833323739";

    let bbsplus_keypair = KeyPair::<BBSplusSha256>::generate(
        &hex::decode(&IKM).unwrap(),
        Some(&hex::decode(&KEY_INFO).unwrap())
    );

    let get_generators_fn = make_generators::<<BBSplusSha256 as Scheme>::Ciphersuite>;

    let generators = global_generators(get_generators_fn, 3);
    print_generators(&generators);

    let message = BBSplusMessage::map_message_to_scalar_as_hash::<Bls12381Sha256>(&hex::decode(msg).unwrap(), Some(&hex::decode(dst_sha256).unwrap()));
    let message_bytes = message.to_bytes_be();
    println!("message: {:?}", hex::encode(message_bytes));

    let mut messages: Vec<BBSplusMessage> = Vec::new();
    messages.push(message);


    let message_to_verify = BBSplusMessage::map_message_to_scalar_as_hash::<Bls12381Sha256>(&hex::decode(msg_wrong).unwrap(), Some(&hex::decode(dst_sha256).unwrap()));
    let mut messages_to_verify: Vec<BBSplusMessage> = Vec::new();
    messages_to_verify.push(message_to_verify);

    let signature = Signature::<BBSplusSha256>::sign(Some(&messages), bbsplus_keypair.private_key(), bbsplus_keypair.public_key(), &generators, Some(&hex::decode(header).unwrap()));
    println!("signature: {}", hex::encode(signature.to_bytes()));
    
    let valid = signature.verify(bbsplus_keypair.public_key(), Some(&messages_to_verify), &generators, Some(&hex::decode(header).unwrap()));
    println!("{}", valid);

    let signature_PoK = PoKSignature::<BBSplusSha256>::proof_gen(signature.bbsPlusSignature(), bbsplus_keypair.public_key(), Some(&messages), &generators, Some(&revealed_message_indexes), Some(&hex::decode(header).unwrap()), Some(&hex::decode(ph).unwrap()), Some(&hex::decode(seed).unwrap()));
    println!("SPoK: {}", hex::encode(signature_PoK.to_bytes()));

    let valid = signature_PoK.proof_verify(bbsplus_keypair.public_key(), Some(&messages), &generators, Some(&revealed_message_indexes), Some(&hex::decode(header).unwrap()), Some(&hex::decode(ph).unwrap()));
    println!("SPoK verify: {}", valid);
}


fn test_cl03_sign() {
    const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const wrong_msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03";

    let cl03_keypair = KeyPair::<CL03Sha256>::generate(None);

    let message = CL03Message::map_message_to_integer_as_hash::<CLSha256>(&hex::decode(msg).unwrap());
    
    let wrong_message = CL03Message::map_message_to_integer_as_hash::<CLSha256>(&hex::decode(wrong_msg).unwrap());

    
    let signature = Signature::<CL03Sha256>::sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &message);

    let bytes = signature.to_bytes();
    // println!("\n signature: {}", hex::encode(&bytes));

    let signature_copy = Signature::<CL03Sha256>::from_bytes(&bytes);

    // println!("\n signature {}", hex::encode(&signature_copy.to_bytes()));

    // println!("compare: {}", signature == signature_copy);

    let valid = signature.verify(cl03_keypair.public_key(), &message);

    println!("valid: {}", valid);

    let valid2 = signature.verify_multiattr(cl03_keypair.public_key(), &[message]);

    println!("valid multiattr: {}", valid2);



}

fn main() {

    // const IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    // const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";


    
    // let cl03_keypair = KeyPair::<CL03Sha256>::generate(None);
    // let bbsplus_keypair = KeyPair::<BBSplusShake256>::generate(
    //     &hex::decode(&IKM).unwrap(),
    //     Some(&hex::decode(&KEY_INFO).unwrap())
    // );

    // println!("BBS+ KeyPair = {:?}", bbsplus_keypair);
    // println!("SK: {}", bbsplus_keypair.private_key().encode());
    // println!("PK: {}", bbsplus_keypair.public_key().encode());



    // println!("CL03 KeyPair = {:?}", cl03_keypair);


    // // Suite specific create generators function
    // let get_generators_fn = make_generators::<<BBSplusShake256 as Scheme>::Ciphersuite>;

    // let generators = global_generators(get_generators_fn, 5);
    // let generators2 = signer_specific_generators(get_generators_fn, 5);

    // print_generators(&generators);

    // prova(&bbsplus_keypair);

    // bbsplus_keypair.write_keypair_to_file(Some("keypair.txt".to_string()));


    // let g1 = G1Affine::generator();
    // let g2 = G2Affine::generator();

    // let write_data_start_time = Instant::now();
    // let p = pairing(&g1,&g2);
    // println!("pairing = {} {:.2?}",p, write_data_start_time.elapsed());


    // let mut rng = rand::thread_rng();
    // let messages = BBSplusMessage::random(&mut rng);
    
    // let commitment = Commitment::<BBSplusShake256>::commit(&[messages], Some(&generators), &[0usize]); 

    // // prova2(commitment);

    // // let sign = BlindSignature::<BBSplusShake256>::blind_sign(pk, sk, commitment);
    // // prova3(sign);

    // test_bbsplus_sign();
    // test_cl03_sign();


    println!("{}", divm(Integer::from(6), Integer::from(12), Integer::from(14)));

    println!("{}", divm(Integer::from(4), Integer::from(8), Integer::from(20)));
    
    println!("{}", divm(Integer::from(0), Integer::from(1), Integer::from(2)));

}