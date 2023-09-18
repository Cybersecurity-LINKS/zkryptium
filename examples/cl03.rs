use digest::Digest;
use links_crypto::{schemes::algorithms::{CL03, Scheme, CL03Sha256, Ciphersuite}, signatures::{commitment::Commitment, blind::BlindSignature, proof::{PoKSignature, ZKPoK}}, cl03::ciphersuites::CLCiphersuite, keys::{pair::KeyPair, cl03_key::CL03CommitmentPublicKey}, utils::message::CL03Message};


fn cl03_main<S: Scheme>() 
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest
{
    const msgs: &[&str] = &["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];
    
    log::info!("Keypair Generation");
    let issuer_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate(Some(msgs.len().try_into().unwrap()));
    
    let messages: Vec<CL03Message> = msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();
    
 
    let unrevealed_message_indexes = [0usize];
    let revealed_message_indexes = [1usize,  2usize];
    let revealed_messages: Vec<CL03Message> = messages.iter().enumerate().filter(|&(i,_)| revealed_message_indexes.contains(&i) ).map(|(_, m)| m.clone()).collect();
    
    log::info!("Computing pedersen commitment on messages");
    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&messages, issuer_keypair.public_key(), Some(&unrevealed_message_indexes));
    
    log::info!("Computation of a Zero-Knowledge proof-of-knowledge of committed messages");
    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), None, issuer_keypair.public_key(), None, &unrevealed_message_indexes);

    log::info!("Verification of the Zero-Knowledge proof and computation of a blind signature");
    let blind_signature = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(issuer_keypair.public_key(), issuer_keypair.private_key(), &zkpok, Some(&revealed_messages), commitment.cl03Commitment(), None, None, &unrevealed_message_indexes, Some(&revealed_message_indexes));
    
    log::info!("Signature unblinding and verification...");
    let unblided_signature = blind_signature.unblind_sign(&commitment);
    let verify = unblided_signature.verify_multiattr(issuer_keypair.public_key(), &messages);

    assert!(verify, "Error! The unblided signature verification should PASS!");
    log::info!("Signature is VALID!");

    //Verifier generates its pk
    log::info!("Generation of a Commitment Public Key for the computation of the SPoK");
    let verifier_commitment_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(Some(issuer_keypair.public_key().N.clone()), Some(msgs.len()));

    //Holder compute the Signature Proof of Knowledge
    log::info!("Computation of a Zero-Knowledge proof-of-knowledge of a signature");
    let signature_pok = PoKSignature::<CL03<S::Ciphersuite>>::proof_gen(unblided_signature.cl03Signature(), &verifier_commitment_pk, issuer_keypair.public_key(), &messages, &unrevealed_message_indexes);
    
    //Verifier verifies the Signature Proof of Knowledge
    log::info!("Signature Proof of Knowledge verification...");
    let valid_proof = signature_pok.proof_verify(&verifier_commitment_pk, issuer_keypair.public_key(), &revealed_messages, &unrevealed_message_indexes, msgs.len());
    
    assert!(valid_proof, "Error! The signature proof of knowledge should PASS!");
    log::info!("Signature Proof of Knowledge is VALID!");
}

fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    println!("\nRunnig CL03 signature algorithm...\n");

    println!("\n");
    log::info!("Ciphersuite: CL03-SHA-256");

    cl03_main::<CL03Sha256>();
}