use digest::Digest;

use crate::{keys::{pair::KeyPair, cl03_key::CL03CommitmentPublicKey}, schemes::algorithms::{CL03Sha256, Scheme, CL03, Ciphersuite}, bbsplus::message::CL03Message, cl03::ciphersuites::CLSha256, signatures::{signature::Signature, commitment::Commitment, proof::ZKPoK, blind::BlindSignature}};

use super::ciphersuites::CLCiphersuite;



pub(crate) fn signature<S: Scheme>() 
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest
{
    const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const wrong_msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03";

    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate(Some(1));

    let message = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(msg).unwrap());
    
    let wrong_message = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(wrong_msg).unwrap());

    let signature = Signature::<CL03<S::Ciphersuite>>::sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &message);

    let valid = signature.verify(cl03_keypair.public_key(), &message);

    assert!(valid, "Error! Signature should be VALID");

    let valid = signature.verify(cl03_keypair.public_key(), &wrong_message);

    assert!(!valid, "Error! Signature should be INVALID");
}


pub(crate) fn zkpok<S: Scheme>()
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest
{
    const msgs: &[&str] = &["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];

    const wrong_msgs: &[&str] = &["7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];

    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate(Some(msgs.len().try_into().unwrap()));

    let messages: Vec<CL03Message> = msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();
    let wrong_messages: Vec<CL03Message> = wrong_msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();

    let unrevealed_message_indexes = [0usize];
    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&messages, cl03_keypair.public_key(), Some(&unrevealed_message_indexes));
    let wrong_commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&wrong_messages, cl03_keypair.public_key(), Some(&unrevealed_message_indexes));
    

    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), None, cl03_keypair.public_key(), None, &unrevealed_message_indexes);

    let valid = zkpok.verify_proof(commitment.cl03Commitment(), None, cl03_keypair.public_key(), None, &unrevealed_message_indexes);

    assert!(valid, "Error! ZKPoK verification should PASS");


    let valid = zkpok.verify_proof(wrong_commitment.cl03Commitment(), None, cl03_keypair.public_key(), None, &unrevealed_message_indexes);

    assert!(!valid, "Error! ZKPok verification should FAIL");


    //Trusted Party Commitment

    let trusted_party_commitment_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(None, Some(msgs.len().try_into().unwrap()));
    let trusted_party_commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_commitment_pk(&messages, &trusted_party_commitment_pk, Some(&unrevealed_message_indexes));
    let trusted_party_commitment_wrong = Commitment::<CL03<S::Ciphersuite>>::commit_with_commitment_pk(&wrong_messages, &trusted_party_commitment_pk, Some(&unrevealed_message_indexes));
    
    
    let zkpok2 = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), Some(trusted_party_commitment.cl03Commitment()), cl03_keypair.public_key(), Some(&trusted_party_commitment_pk), &unrevealed_message_indexes);

    let valid = zkpok2.verify_proof(commitment.cl03Commitment(), Some(trusted_party_commitment.cl03Commitment()), cl03_keypair.public_key(), Some(&trusted_party_commitment_pk), &unrevealed_message_indexes);

    assert!(valid, "Error! ZKPoK verification should PASS");

    let zkpok2_wrong_tp_commitment = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), Some(trusted_party_commitment_wrong.cl03Commitment()), cl03_keypair.public_key(), Some(&trusted_party_commitment_pk), &unrevealed_message_indexes);

    let valid = zkpok2_wrong_tp_commitment.verify_proof(commitment.cl03Commitment(), Some(trusted_party_commitment.cl03Commitment()), cl03_keypair.public_key(), Some(&trusted_party_commitment_pk), &unrevealed_message_indexes);

    assert!(!valid, "Error! ZKPoK verification should FAIL");


}


pub(crate) fn blind_sign<S: Scheme>() 
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest

{
    const msgs: &[&str] = &["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];
    const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const wrong_msgs: &[&str] = &["7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];

    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate(Some(msgs.len().try_into().unwrap()));
    //TODO: Fails with multuple messages!
    let messages: Vec<CL03Message> = msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();
    let msg_intger = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(msg).unwrap());
    let messages = [msg_intger.clone()];
    let wrong_messages: Vec<CL03Message> = wrong_msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();


    let unrevealed_message_indexes = [0usize];
    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&messages, cl03_keypair.public_key(), Some(&unrevealed_message_indexes));
    let wrong_commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&wrong_messages, cl03_keypair.public_key(), Some(&unrevealed_message_indexes));

    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), None, cl03_keypair.public_key(), None, &unrevealed_message_indexes);

    let blind_signature = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &commitment, &zkpok, commitment.cl03Commitment(), None, None, &unrevealed_message_indexes);
    let unblided_signature = Signature::<CL03<S::Ciphersuite>>::CL03(blind_signature.unblind_sign(&commitment));
    let verify = unblided_signature.verify_multiattr(cl03_keypair.public_key(), &messages);

    assert!(verify, "Error! The unblided signature verification should PASS!");


}