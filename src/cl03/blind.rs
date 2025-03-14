// Copyright 2025 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{
    commitment::CL03Commitment,
    keys::{CL03CommitmentPublicKey, CL03PublicKey, CL03SecretKey},
    signature::CL03Signature,
};
use crate::{
    cl03::{bases::Bases, ciphersuites::CLCiphersuite},
    schemes::algorithms::CL03,
    schemes::generics::{BlindSignature, Commitment, Signature, ZKPoK},
    utils::message::cl03_message::CL03Message,
    utils::random::{random_bits, random_prime},
};
use digest::Digest;
use rug::{ops::Pow, Integer};
use serde::{Deserialize, Serialize};
use std::panic;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03BlindSignature {
    pub(crate) e: Integer,
    pub(crate) rprime: Integer,
    pub(crate) v: Integer,
}

impl<CS: CLCiphersuite> BlindSignature<CL03<CS>> {
    pub fn e(&self) -> &Integer {
        match self {
            Self::CL03(inner) => &inner.e,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn rprime(&self) -> &Integer {
        match self {
            Self::CL03(inner) => &inner.rprime,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn v(&self) -> &Integer {
        match self {
            Self::CL03(inner) => &inner.v,
            _ => panic!("Cannot happen!"),
        }
    }

    //TODO: ("remove the indexes");

    pub fn blind_sign(
        pk: &CL03PublicKey,
        sk: &CL03SecretKey,
        a_bases: &Bases,
        zkpok: &ZKPoK<CL03<CS>>,
        revealed_messages: Option<&[CL03Message]>,
        C: &CL03Commitment,
        C_trusted: Option<&CL03Commitment>,
        commitment_pk: Option<&CL03CommitmentPublicKey>,
        unrevealed_message_indexes: &[usize],
        revealed_message_indexes: Option<&[usize]>,
    ) -> Self
    where
        CS::HashAlg: Digest,
    {
        if !zkpok.verify_proof(
            C,
            C_trusted,
            pk,
            a_bases,
            commitment_pk,
            unrevealed_message_indexes,
        ) {
            panic!("Knowledge of committed secrets not verified");
        }

        let mut extended_commitment: Commitment<CL03<CS>> = Commitment::CL03(C.clone());
        if revealed_messages.is_some() && revealed_message_indexes.is_some() {
            extended_commitment.extend_commitment_with_pk(
                revealed_messages.unwrap(),
                pk,
                a_bases,
                revealed_message_indexes,
            );
        }
        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));
        while ((&e > &Integer::from(2).pow(CS::le - 1))
            && (&e < &Integer::from(2).pow(CS::le))
            && (Integer::from(e.gcd_ref(&phi_n)) == 1))
            == false
        {
            e = random_prime(CS::le);
        }

        let rprime = random_bits(CS::ls);
        let e2n = Integer::from(e.invert_ref(&phi_n).unwrap());

        // v = powmod(((Cx) * powmod(pk['b'], rprime, pk['N']) * pk['c']), e2n, pk['N'])
        let v = Integer::from(
            (extended_commitment.value()
                * Integer::from(pk.b.pow_mod_ref(&rprime, &pk.N).unwrap())
                * &pk.c)
                .pow_mod_ref(&e2n, &pk.N)
                .unwrap(),
        );
        let sig = CL03BlindSignature { e, rprime, v };
        // sig = { 'e':e, 'rprime':rprime, 'v':v }

        Self::CL03(sig)
    }

    pub fn unblind_sign(&self, commitment: &Commitment<CL03<CS>>) -> Signature<CL03<CS>> {
        let s = commitment.randomness().clone() + self.rprime();
        Signature::CL03(CL03Signature {
            e: self.e().clone(),
            s,
            v: self.v().clone(),
        })
    }

    pub fn update_signature(
        &self,
        revealed_messages: Option<&[CL03Message]>,
        C: &CL03Commitment,
        sk: &CL03SecretKey,
        pk: &CL03PublicKey,
        a_bases: &Bases,
        revealed_message_indexes: Option<&[usize]>,
    ) -> Self {
        let mut extended_commitment: Commitment<CL03<CS>> = Commitment::CL03(C.clone());
        if revealed_messages.is_some() && revealed_message_indexes.is_some() {
            extended_commitment.extend_commitment_with_pk(
                revealed_messages.unwrap(),
                pk,
                a_bases,
                revealed_message_indexes,
            );
        }

        let phi_N = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));
        let e2n = Integer::from(self.e().invert_ref(&phi_N).unwrap());

        let v = Integer::from(
            (extended_commitment.value()
                * Integer::from(pk.b.pow_mod_ref(self.rprime(), &pk.N).unwrap())
                * &pk.c)
                .pow_mod_ref(&e2n, &pk.N)
                .unwrap(),
        );

        let sig = CL03BlindSignature {
            e: self.e().clone(),
            rprime: self.rprime().clone(),
            v,
        };
        Self::CL03(sig)
    }
}

#[cfg(test)]
mod tests {

    use crate::cl03::ciphersuites::CLCiphersuite;
    use crate::schemes::algorithms::CL03_CL1024_SHA256;
    use crate::{
        cl03::bases::Bases,
        keys::pair::KeyPair,
        schemes::algorithms::{Ciphersuite, Scheme, CL03},
        schemes::generics::{BlindSignature, Commitment, ZKPoK},
        utils::message::cl03_message::CL03Message,
    };
    use digest::Digest;

    //Blind signature - CL1024-SHA256
    #[test]
    fn blind_sign_cl1024_sha256() {
        blind_sign::<CL03_CL1024_SHA256>();
    }

    //Blind Signature update - CL1024-SHA256
    #[test]
    fn update_signature_cl1024_sha256() {
        update_signature::<CL03_CL1024_SHA256>();
    }

    fn blind_sign<S: Scheme>()
    where
        S::Ciphersuite: CLCiphersuite,
        <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
    {
        const msgs: &[&str] = &[
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
        ];
        // const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
        const wrong_msgs: &[&str] = &[
            "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
            "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
        ];

        let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
        let a_bases = Bases::generate(cl03_keypair.public_key(), msgs.len());

        let messages: Vec<CL03Message> = msgs
            .iter()
            .map(|&m| {
                CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                    &hex::decode(m).unwrap(),
                )
            })
            .collect();
        // let msg_intger = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(msg).unwrap());
        // let messages = [msg_intger.clone()];
        let wrong_messages: Vec<CL03Message> = wrong_msgs
            .iter()
            .map(|&m| {
                CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                    &hex::decode(m).unwrap(),
                )
            })
            .collect();

        let unrevealed_message_indexes = [0usize];
        let revealed_message_indexes = [1usize, 2usize];
        let revealed_messages: Vec<CL03Message> = messages
            .iter()
            .enumerate()
            .filter(|&(i, _)| revealed_message_indexes.contains(&i))
            .map(|(_, m)| m.clone())
            .collect();
        let revealed_messages_wrong: Vec<CL03Message> = wrong_messages
            .iter()
            .enumerate()
            .filter(|&(i, _)| revealed_message_indexes.contains(&i))
            .map(|(_, m)| m.clone())
            .collect();

        let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(
            &messages,
            cl03_keypair.public_key(),
            &a_bases,
            Some(&unrevealed_message_indexes),
        );

        let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
            &messages,
            commitment.cl03Commitment(),
            None,
            cl03_keypair.public_key(),
            &a_bases,
            None,
            &unrevealed_message_indexes,
        );

        let blind_signature = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(
            cl03_keypair.public_key(),
            cl03_keypair.private_key(),
            &a_bases,
            &zkpok,
            Some(&revealed_messages),
            commitment.cl03Commitment(),
            None,
            None,
            &unrevealed_message_indexes,
            Some(&revealed_message_indexes),
        );
        let unblided_signature = blind_signature.unblind_sign(&commitment);
        let verify =
            unblided_signature.verify_multiattr(cl03_keypair.public_key(), &a_bases, &messages);

        assert!(
            verify,
            "Error! The unblided signature verification should PASS!"
        );

        let blind_signature_wrong = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(
            cl03_keypair.public_key(),
            cl03_keypair.private_key(),
            &a_bases,
            &zkpok,
            Some(&revealed_messages_wrong),
            commitment.cl03Commitment(),
            None,
            None,
            &unrevealed_message_indexes,
            Some(&revealed_message_indexes),
        );
        let unblided_signature_wrong = blind_signature_wrong.unblind_sign(&commitment);
        let verify = unblided_signature_wrong.verify_multiattr(
            cl03_keypair.public_key(),
            &a_bases,
            &messages,
        );

        assert!(
            !verify,
            "Error! The unblinded signature verification SHOULD FAIL!"
        );
    }

    pub(crate) fn update_signature<S: Scheme>()
    where
        S::Ciphersuite: CLCiphersuite,
        <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
    {
        const msgs: &[&str] = &[
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
        ];
        const updated_msgs: &[&str] = &[
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
        ];

        let n_attr = msgs.len();
        let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
        let a_bases = Bases::generate(cl03_keypair.public_key(), n_attr);

        let messages: Vec<CL03Message> = msgs
            .iter()
            .map(|&m| {
                CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                    &hex::decode(m).unwrap(),
                )
            })
            .collect();
        let updated_messages: Vec<CL03Message> = updated_msgs
            .iter()
            .map(|&m| {
                CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                    &hex::decode(m).unwrap(),
                )
            })
            .collect();

        let unrevealed_message_indexes = [0usize];
        let revealed_message_indexes = [1usize, 2usize];
        let revealed_messages: Vec<CL03Message> = messages
            .iter()
            .enumerate()
            .filter(|&(i, _)| revealed_message_indexes.contains(&i))
            .map(|(_, m)| m.clone())
            .collect();
        let revealed_updated_messages: Vec<CL03Message> = updated_messages
            .iter()
            .enumerate()
            .filter(|&(i, _)| revealed_message_indexes.contains(&i))
            .map(|(_, m)| m.clone())
            .collect();
        let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(
            &messages,
            cl03_keypair.public_key(),
            &a_bases,
            Some(&unrevealed_message_indexes),
        );

        let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
            &messages,
            commitment.cl03Commitment(),
            None,
            cl03_keypair.public_key(),
            &a_bases,
            None,
            &unrevealed_message_indexes,
        );

        let blind_signature = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(
            cl03_keypair.public_key(),
            cl03_keypair.private_key(),
            &a_bases,
            &zkpok,
            Some(&revealed_messages),
            commitment.cl03Commitment(),
            None,
            None,
            &unrevealed_message_indexes,
            Some(&revealed_message_indexes),
        );
        let unblided_signature = blind_signature.unblind_sign(&commitment);
        let verify =
            unblided_signature.verify_multiattr(cl03_keypair.public_key(), &a_bases, &messages);

        assert!(
            verify,
            "Error! The unblided signature verification should PASS!"
        );

        let updated_signature = blind_signature.update_signature(
            Some(&revealed_updated_messages),
            &commitment.cl03Commitment(),
            cl03_keypair.private_key(),
            cl03_keypair.public_key(),
            &a_bases,
            Some(&revealed_message_indexes),
        );
        let unblinded_updated_signature = updated_signature.unblind_sign(&commitment);

        let verify = unblinded_updated_signature.verify_multiattr(
            cl03_keypair.public_key(),
            &a_bases,
            &updated_messages,
        );
        assert!(
            verify,
            "Error! The unblided signature verification should PASS!"
        );
    }
}
