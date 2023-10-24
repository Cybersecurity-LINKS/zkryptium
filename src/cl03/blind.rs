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


use std::panic;
use digest::Digest;
use rug::{Integer, ops::Pow};
use serde::{Deserialize, Serialize};
use crate::{schemes::algorithms::CL03, utils::message::CL03Message, cl03::{ciphersuites::CLCiphersuite, bases::Bases}, utils::random::{random_prime, random_bits}, schemes::generics::{BlindSignature, Commitment, Signature, ZKPoK}};
use super::{keys::{CL03SecretKey, CL03PublicKey, CL03CommitmentPublicKey}, commitment::CL03Commitment, signature::CL03Signature};




#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03BlindSignature {
    pub(crate) e: Integer,
    pub(crate) rprime: Integer,
    pub(crate) v: Integer,
}


impl <CS:CLCiphersuite> BlindSignature<CL03<CS>> {

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

    pub fn blind_sign(pk: &CL03PublicKey, sk: &CL03SecretKey, a_bases: &Bases, zkpok: &ZKPoK<CL03<CS>>, revealed_messages: Option<&[CL03Message]>, C: &CL03Commitment, C_trusted: Option<&CL03Commitment>, commitment_pk: Option<&CL03CommitmentPublicKey>, unrevealed_message_indexes: &[usize], revealed_message_indexes: Option<&[usize]>) -> Self
    where
        CS::HashAlg: Digest
    {

        if !zkpok.verify_proof(C, C_trusted, pk, a_bases, commitment_pk, unrevealed_message_indexes) {
            panic!("Knowledge of committed secrets not verified");
        }

        let mut extended_commitment: Commitment<CL03<CS>> = Commitment::CL03(C.clone());
        if revealed_messages.is_some() && revealed_message_indexes.is_some() { 
            extended_commitment.extend_commitment_with_pk(revealed_messages.unwrap(), pk, a_bases, revealed_message_indexes);
        }
        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));
        while ((&e > &Integer::from(2).pow(CS::le-1)) && (&e < &Integer::from(2).pow(CS::le)) && (Integer::from(e.gcd_ref(&phi_n)) == 1)) == false {
            e = random_prime(CS::le);
        }

        let rprime = random_bits(CS::ls);
        let e2n = Integer::from(e.invert_ref(&phi_n).unwrap());

        // v = powmod(((Cx) * powmod(pk['b'], rprime, pk['N']) * pk['c']), e2n, pk['N'])
        let v = Integer::from((extended_commitment.value() * Integer::from(pk.b.pow_mod_ref(&rprime, &pk.N).unwrap()) * &pk.c).pow_mod_ref(&e2n, &pk.N).unwrap());
        let sig = CL03BlindSignature{e, rprime, v};
        // sig = { 'e':e, 'rprime':rprime, 'v':v }

        Self::CL03(sig)

    }

    pub fn unblind_sign(&self, commitment: &Commitment<CL03<CS>>) -> Signature<CL03<CS>> {
        let s = commitment.randomness().clone() + self.rprime();
        Signature::CL03(CL03Signature { e: self.e().clone(), s, v: self.v().clone()})
    }

    pub fn update_signature(&self, revealed_messages: Option<&[CL03Message]>, C: &CL03Commitment, sk: &CL03SecretKey, pk: &CL03PublicKey, a_bases: &Bases,  revealed_message_indexes: Option<&[usize]>) -> Self {
        let mut extended_commitment: Commitment<CL03<CS>> = Commitment::CL03(C.clone());
        if revealed_messages.is_some() && revealed_message_indexes.is_some() { 
            extended_commitment.extend_commitment_with_pk(revealed_messages.unwrap(), pk, a_bases, revealed_message_indexes);
        }

        let phi_N = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));
        let e2n = Integer::from(self.e().invert_ref(&phi_N).unwrap());

        let v = Integer::from((extended_commitment.value() * Integer::from(pk.b.pow_mod_ref(self.rprime(), &pk.N).unwrap()) * &pk.c).pow_mod_ref(&e2n, &pk.N).unwrap());
    
        let sig = CL03BlindSignature{e: self.e().clone(), rprime: self.rprime().clone(), v};
        Self::CL03(sig)
    }
}