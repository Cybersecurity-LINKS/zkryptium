use std::time::Instant;

use bls12_381_plus::{G1Affine, G2Affine, pairing, G1Projective, Scalar};
use byteorder::BigEndian;
use glass_pumpkin::prime::new;
use hex::ToHex;
use links_crypto::{utils::random, keys::{cl03_key::{CL03PublicKey, CL03CommitmentPublicKey}, pair::{KeyPair}, bbsplus_key::{BBSplusSecretKey, BBSplusPublicKey}}, bbsplus::{generators::{make_generators, global_generators, signer_specific_generators, print_generators}, ciphersuites::{Bls12381Shake256, BbsCiphersuite, Bls12381Sha256}, message::{Message, BBSplusMessage, CL03Message}}, schemes::algorithms::{CL03, BBSplus, Scheme, CL03Sha256, BBSplusShake256, BBSplusSha256}, signatures::{commitment::{Commitment, BBSplusCommitment, self}, blind::{self, BlindSignature, BBSplusBlindSignature}, signature::{BBSplusSignature, Signature}, proof::{PoKSignature, CL03PoKSignature, NISPSignaturePoK}}, cl03::ciphersuites::CLSha256};

use links_crypto::keys::key::PrivateKey;
use rug::{Integer, Complete};


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
    const msg2: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03";
    const wrong_msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03";

    let cl03_keypair = KeyPair::<CL03Sha256>::generate(Some(2));
    let commitment_pk = CL03CommitmentPublicKey::generate::<CLSha256>(Some(cl03_keypair.public_key().N.clone()), Some(2));

    let message = CL03Message::map_message_to_integer_as_hash::<CLSha256>(&hex::decode(msg).unwrap());
    let message2 = CL03Message::map_message_to_integer_as_hash::<CLSha256>(&hex::decode(msg2).unwrap());
    let messages = [message.clone()];
    
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

    let unrevealed_message_indexes = [0usize];
    let commitment = Commitment::<CL03Sha256>::commit_with_pk(&messages, cl03_keypair.public_key(), Some(&unrevealed_message_indexes));
    let blind_signature = BlindSignature::<CL03Sha256>::blind_sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &commitment);
    let unblided_signature = Signature::<CL03Sha256>::CL03(blind_signature.unblind_sign(&commitment));
    let verify = unblided_signature.verify_multiattr(cl03_keypair.public_key(), &messages);

    println!("valid signature multimessage: {}", verify);

    let signature_pok = NISPSignaturePoK::nisp5_MultiAttr_generate_proof::<CLSha256>(unblided_signature.cl03Signature(), &commitment_pk, cl03_keypair.public_key(), &messages, &unrevealed_message_indexes);

    let valid_proof = signature_pok.nisp5_MultiAttr_verify_proof::<CLSha256>(&commitment_pk, cl03_keypair.public_key(), &messages, &unrevealed_message_indexes);
    println!("valid proof: {}", valid_proof);

}

fn main() {
    // test_bbsplus_sign();
    // test_cl03_sign();
}