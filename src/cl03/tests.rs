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

use digest::Digest;

use crate::{keys::{pair::KeyPair, cl03_key::CL03CommitmentPublicKey}, schemes::algorithms::{Scheme, CL03, Ciphersuite}, utils::message::CL03Message, signatures::{signature::Signature, commitment::Commitment, proof::{ZKPoK, PoKSignature}, blind::BlindSignature}, cl03::bases::Bases};

use super::ciphersuites::CLCiphersuite;



pub(crate) fn signature<S: Scheme>() 
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest
{
    const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const wrong_msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03";

    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
    let a_bases = Bases::generate(cl03_keypair.public_key(), 1);

    let message = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(msg).unwrap());
    
    let wrong_message = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(wrong_msg).unwrap());

    let signature = Signature::<CL03<S::Ciphersuite>>::sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &a_bases, &message);

    let valid = signature.verify(cl03_keypair.public_key(), &a_bases, &message);

    assert!(valid, "Error! Signature should be VALID");

    let valid = signature.verify(cl03_keypair.public_key(), &a_bases, &wrong_message);

    assert!(!valid, "Error! Signature should be INVALID");
}


pub(crate) fn zkpok<S: Scheme>()
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest
{
    const msgs: &[&str] = &["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];

    const wrong_msgs: &[&str] = &["7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];

    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
    let a_bases = Bases::generate(cl03_keypair.public_key(), msgs.len());

    let messages: Vec<CL03Message> = msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();
    let wrong_messages: Vec<CL03Message> = wrong_msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();

    let unrevealed_message_indexes = [0usize];
    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&messages, cl03_keypair.public_key(), &a_bases, Some(&unrevealed_message_indexes));
    let wrong_commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&wrong_messages, cl03_keypair.public_key(), &a_bases, Some(&unrevealed_message_indexes));
    

    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), None, cl03_keypair.public_key(), &a_bases, None, &unrevealed_message_indexes);

    let valid = zkpok.verify_proof(commitment.cl03Commitment(), None, cl03_keypair.public_key(), &a_bases, None, &unrevealed_message_indexes);

    assert!(valid, "Error! ZKPoK verification should PASS");


    let valid = zkpok.verify_proof(wrong_commitment.cl03Commitment(), None, cl03_keypair.public_key(), &a_bases, None, &unrevealed_message_indexes);

    assert!(!valid, "Error! ZKPok verification should FAIL");


    //Trusted Party Commitment

    let trusted_party_commitment_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(None, Some(msgs.len().try_into().unwrap()));
    let trusted_party_commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_commitment_pk(&messages, &trusted_party_commitment_pk, Some(&unrevealed_message_indexes));
    let trusted_party_commitment_wrong = Commitment::<CL03<S::Ciphersuite>>::commit_with_commitment_pk(&wrong_messages, &trusted_party_commitment_pk, Some(&unrevealed_message_indexes));
    
    
    let zkpok2 = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), Some(trusted_party_commitment.cl03Commitment()), cl03_keypair.public_key(), &a_bases, Some(&trusted_party_commitment_pk), &unrevealed_message_indexes);

    let valid = zkpok2.verify_proof(commitment.cl03Commitment(), Some(trusted_party_commitment.cl03Commitment()), cl03_keypair.public_key(), &a_bases, Some(&trusted_party_commitment_pk), &unrevealed_message_indexes);

    assert!(valid, "Error! ZKPoK verification should PASS");

    let zkpok2_wrong_tp_commitment = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), Some(trusted_party_commitment_wrong.cl03Commitment()), cl03_keypair.public_key(), &a_bases, Some(&trusted_party_commitment_pk), &unrevealed_message_indexes);

    let valid = zkpok2_wrong_tp_commitment.verify_proof(commitment.cl03Commitment(), Some(trusted_party_commitment.cl03Commitment()), cl03_keypair.public_key(), &a_bases, Some(&trusted_party_commitment_pk), &unrevealed_message_indexes);

    assert!(!valid, "Error! ZKPoK verification should FAIL");


}


pub(crate) fn blind_sign<S: Scheme>() 
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest
{

    const msgs: &[&str] = &["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];
    // const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const wrong_msgs: &[&str] = &["7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];

    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
    let a_bases = Bases::generate(cl03_keypair.public_key(), msgs.len());

    let messages: Vec<CL03Message> = msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();
    // let msg_intger = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(msg).unwrap());
    // let messages = [msg_intger.clone()];
    let wrong_messages: Vec<CL03Message> = wrong_msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();

 
    let unrevealed_message_indexes = [0usize];
    let revealed_message_indexes = [1usize,  2usize];
    let revealed_messages: Vec<CL03Message> = messages.iter().enumerate().filter(|&(i,_)| revealed_message_indexes.contains(&i) ).map(|(_, m)| m.clone()).collect();
    let revealed_messages_wrong : Vec<CL03Message> = wrong_messages.iter().enumerate().filter(|&(i,_)| revealed_message_indexes.contains(&i) ).map(|(_, m)| m.clone()).collect();

    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&messages, cl03_keypair.public_key(), &a_bases, Some(&unrevealed_message_indexes));
    let wrong_commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&wrong_messages, cl03_keypair.public_key(), &a_bases, Some(&unrevealed_message_indexes));

    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), None, cl03_keypair.public_key(), &a_bases, None, &unrevealed_message_indexes);

    let blind_signature = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &a_bases, &zkpok, Some(&revealed_messages), commitment.cl03Commitment(), None, None, &unrevealed_message_indexes, Some(&revealed_message_indexes));
    let unblided_signature = blind_signature.unblind_sign(&commitment);
    let verify = unblided_signature.verify_multiattr(cl03_keypair.public_key(), &a_bases, &messages);

    assert!(verify, "Error! The unblided signature verification should PASS!");


    let blind_signature_wrong = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &a_bases, &zkpok, Some(&revealed_messages_wrong), commitment.cl03Commitment(), None, None, &unrevealed_message_indexes, Some(&revealed_message_indexes));
    let unblided_signature_wrong = blind_signature_wrong.unblind_sign(&commitment);
    let verify = unblided_signature_wrong.verify_multiattr(cl03_keypair.public_key(), &a_bases, &messages);

    assert!(!verify, "Error! The unblinded signature verification SHOULD FAIL!");


}


pub(crate) fn spok<S: Scheme>() 
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest
{
    const msgs: &[&str] = &["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];
    // const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const wrong_msgs: &[&str] = &["7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];

    
    let n_attr = msgs.len();
    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
    let a_bases = Bases::generate(cl03_keypair.public_key(), n_attr);


    let messages: Vec<CL03Message> = msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();
    // let msg_intger = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(msg).unwrap());
    // let messages = [msg_intger.clone()];
    let wrong_messages: Vec<CL03Message> = wrong_msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();

 
    let unrevealed_message_indexes = [0usize];
    let revealed_message_indexes = [1usize,  2usize];
    let revealed_messages: Vec<CL03Message> = messages.iter().enumerate().filter(|&(i,_)| revealed_message_indexes.contains(&i) ).map(|(_, m)| m.clone()).collect();
    let revealed_messages_wrong : Vec<CL03Message> = wrong_messages.iter().enumerate().filter(|&(i,_)| revealed_message_indexes.contains(&i) ).map(|(_, m)| m.clone()).collect();

    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&messages, cl03_keypair.public_key(), &a_bases, Some(&unrevealed_message_indexes));
    let wrong_commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&wrong_messages, cl03_keypair.public_key(), &a_bases, Some(&unrevealed_message_indexes));

    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), None, cl03_keypair.public_key(), &a_bases, None, &unrevealed_message_indexes);

    let blind_signature = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &a_bases, &zkpok, Some(&revealed_messages), commitment.cl03Commitment(), None, None, &unrevealed_message_indexes, Some(&revealed_message_indexes));
    let unblided_signature = blind_signature.unblind_sign(&commitment);
    let verify = unblided_signature.verify_multiattr(cl03_keypair.public_key(), &a_bases, &messages);

    assert!(verify, "Error! The unblided signature verification should PASS!");


    let blind_signature_wrong = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &a_bases, &zkpok, Some(&revealed_messages_wrong), commitment.cl03Commitment(), None, None, &unrevealed_message_indexes, Some(&revealed_message_indexes));
    let unblided_signature_wrong = blind_signature_wrong.unblind_sign(&commitment);
    let verify = unblided_signature_wrong.verify_multiattr(cl03_keypair.public_key(), &a_bases, &messages);

    assert!(!verify, "Error! The unblinded signature verification SHOULD FAIL!");


    let commitment_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(Some(cl03_keypair.public_key().N.clone()), Some(n_attr));


    let signature_pok = PoKSignature::<CL03<S::Ciphersuite>>::proof_gen(unblided_signature.cl03Signature(), &commitment_pk, cl03_keypair.public_key(), &a_bases, &messages, &unrevealed_message_indexes);
    let valid_proof = signature_pok.proof_verify(&commitment_pk, cl03_keypair.public_key(), &a_bases, &revealed_messages, &unrevealed_message_indexes, n_attr);
    
    assert!(valid_proof, "Error! The signature proof of knowledge should PASS!");

    let signature_pok = PoKSignature::<CL03<S::Ciphersuite>>::proof_gen(unblided_signature.cl03Signature(), &commitment_pk, cl03_keypair.public_key(), &a_bases, &messages, &unrevealed_message_indexes);
    let valid_proof = signature_pok.proof_verify(&commitment_pk, cl03_keypair.public_key(), &a_bases, &revealed_messages_wrong, &unrevealed_message_indexes, n_attr);
    
    assert!(!valid_proof, "Error! The signature proof of knowledge should FAIL!");

}


pub(crate) fn update_signature<S: Scheme>()
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest
{
    const msgs: &[&str] = &["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];
    const updated_msgs: &[&str] = &["9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03", "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04"];

    let n_attr = msgs.len();
    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
    let a_bases = Bases::generate(cl03_keypair.public_key(), n_attr);


    let messages: Vec<CL03Message> = msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();
    let updated_messages: Vec<CL03Message> = updated_msgs.iter().map(|&m| CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(m).unwrap()) ).collect();
  
    let unrevealed_message_indexes = [0usize];
    let revealed_message_indexes = [1usize,  2usize];
    let revealed_messages: Vec<CL03Message> = messages.iter().enumerate().filter(|&(i,_)| revealed_message_indexes.contains(&i) ).map(|(_, m)| m.clone()).collect();
    let revealed_updated_messages: Vec<CL03Message> = updated_messages.iter().enumerate().filter(|&(i,_)| revealed_message_indexes.contains(&i) ).map(|(_, m)| m.clone()).collect();
    let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(&messages, cl03_keypair.public_key(), &a_bases, Some(&unrevealed_message_indexes));
    
    let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(&messages, commitment.cl03Commitment(), None, cl03_keypair.public_key(), &a_bases, None, &unrevealed_message_indexes);

    let blind_signature = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(cl03_keypair.public_key(), cl03_keypair.private_key(), &a_bases, &zkpok, Some(&revealed_messages), commitment.cl03Commitment(), None, None, &unrevealed_message_indexes, Some(&revealed_message_indexes));
    let unblided_signature = blind_signature.unblind_sign(&commitment);
    let verify = unblided_signature.verify_multiattr(cl03_keypair.public_key(), &a_bases, &messages);

    assert!(verify, "Error! The unblided signature verification should PASS!");



    let updated_signature = blind_signature.update_signature(Some(&revealed_updated_messages), &commitment.cl03Commitment(), cl03_keypair.private_key(), cl03_keypair.public_key(), &a_bases, Some(&revealed_message_indexes));
    let unblinded_updated_signature = updated_signature.unblind_sign(&commitment);

    let verify = unblinded_updated_signature.verify_multiattr(cl03_keypair.public_key(), &a_bases, &updated_messages);
    assert!(verify, "Error! The unblided signature verification should PASS!");


}