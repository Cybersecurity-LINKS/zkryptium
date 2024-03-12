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
use bls12_381_plus::{G1Projective, Scalar, G1Affine};
use elliptic_curve::{group::Curve, subtle::{CtOption, Choice}, hash2curve::ExpandMsg};
use serde::{Deserialize, Serialize};
use crate::{schemes::algorithms::BBSplus, utils::message::BBSplusMessage, bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, utils::util::bbsplus_utils::{calculate_domain, ScalarExt, hash_to_scalar_old}, schemes::generics::{BlindSignature, Signature, ZKPoK}, errors::Error};
use super::{commitment::BBSplusCommitment, keys::{BBSplusSecretKey, BBSplusPublicKey}, signature::BBSplusSignature};



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusBlindSignature {
    pub(crate) a: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s_second: Scalar,
}


impl <CS:BbsCiphersuite> BlindSignature<BBSplus<CS>> {

    // pub fn blind_sign()

    // pub fn blind_sign(revealed_messages: &[BBSplusMessage], commitment: &BBSplusCommitment, zkpok: &ZKPoK<BBSplus<CS>>, sk: &BBSplusSecretKey, pk: &BBSplusPublicKey, generators: Option<&Generators>, revealed_message_indexes: &[usize], unrevealed_message_indexes: &[usize], nonce: &[u8], header: Option<&[u8]>) -> Result<Self, Error>
    // where
    //     CS::Expander: for<'a> ExpandMsg<'a>,
    // {
    //         let K = revealed_message_indexes.len();
    //         if revealed_messages.len() != K {
    //             return Err(Error::BlindSignError(
    //                 "len(known_messages) != len(revealed_message_indexes)".to_string(),
    //             ));
    //         }

    //         let header = header.unwrap_or(b"");

    //         let U = unrevealed_message_indexes.len();
    //         let L = K + U;

    //         let generators = match generators {
    //             Some(gens) => gens.clone(),
    //             None => {
    //                 let gens = Generators::create::<CS>(L);
    //                 gens
    //             }
                
    //         };

    //         let domain = calculate_domain::<CS>(pk, generators.q1, generators.q1, &generators.message_generators[0..L], Some(header));
            
    //         let mut e_s_for_hash: Vec<u8> = Vec::new();
    //         e_s_for_hash.extend_from_slice(&sk.0.to_bytes_be());
    //         e_s_for_hash.extend_from_slice(&domain.to_bytes_be());
    //         revealed_messages.iter().for_each(|m| e_s_for_hash.extend_from_slice(&m.value.to_bytes_be()));
    //         // e = HASH(PRF(8 \* ceil(log2(r)))) mod r
    //         // s'' = HASH(PRF(8 \* ceil(log2(r)))) mod r
    //         let e_s = hash_to_scalar_old::<CS>(&e_s_for_hash, 2, None);
    //         let e = e_s[0];
    //         let s_second = e_s[1];

    //         // if BlindMessagesProofVerify(commitment, nizk, CGIdxs, nonce) is INVALID abort

    //         // if !zkpok.verify_proof(commitment, &generators, unrevealed_message_indexes, nonce){
    //         //     return Err(Error::BlindSignError(
    //         //         "Knowledge of committed secrets not verified".to_string(),
    //         //     ));
    //         // }

    //         for i in revealed_message_indexes {
    //             if unrevealed_message_indexes.contains(i) {
    //                 return Err(Error::BlindSignError(
    //                     "revealed_message_indexes in unrevealed_message_indexes".to_string(),
    //                 ));
    //             }
    //         }

    //         // b = commitment + P1 + h0 * s'' + h[j1] * msg[1] + ... + h[jK] * msg[K]
    //         let mut B = commitment.value + generators.g1_base_point + generators.q1 * s_second + generators.q1 * domain;


    //         for j in 0..K {
    //             B += generators.message_generators.get(revealed_message_indexes[j]).expect("index overflow") * revealed_messages.get(j).expect("index overflow").value;
    //         }

    //         let SK_plus_e = sk.0 + e;

    //         let A = B * SK_plus_e.invert().unwrap();

    //         if A == G1Projective::IDENTITY{
    //             return Err(Error::BlindSignError("A == IDENTITY G1".to_string()));
    //         }
    //         Ok(Self::BBSplus(BBSplusBlindSignature{a: A, e, s_second}))

    // }

    // pub fn unblind_sign(&self, commitment: &BBSplusCommitment) -> Signature<BBSplus<CS>> {
    //     let s = commitment.s_prime + self.s_second();

    //     Signature::<BBSplus<CS>>::BBSplus(BBSplusSignature{ a: self.a(), e: self.e()})
    // }

    // pub fn update_signature(&self, sk: &BBSplusSecretKey, generators: &Generators, old_message: &BBSplusMessage, new_message: &BBSplusMessage, update_index: usize) -> Self {

    //     if generators.message_generators.len() <= update_index {
    //         panic!("len(generators) <= update_index");
    //     }
    //     let H_i = generators.message_generators.get(update_index).expect("index overflow");
    //     let SK_plus_e = sk.0 + self.e();
    //     let mut B = self.a() * SK_plus_e;
    //     B = B + (-H_i * old_message.value);
    //     B = B + (H_i * new_message.value);
    //     let A = B * SK_plus_e.invert().unwrap();

    //     if A == G1Projective::IDENTITY{
    //         panic!("A == IDENTITY G1");
    //     }

    //     return Self::BBSplus(BBSplusBlindSignature { a: A, e: self.e(), s_second: self.s_second() })
    // }

    pub fn a(&self) -> G1Projective {
        match self {
            Self::BBSplus(inner) => inner.a,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn e(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.e,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn s_second(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.s_second,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn to_bytes(&self) -> [u8; 112] {
        let mut bytes = [0u8; 112];
        bytes[0..48].copy_from_slice(&self.a().to_affine().to_compressed());
        let e = self.e().to_be_bytes();
        // e.reverse();
        bytes[48..80].copy_from_slice(&e[..]);
        let s_second = self.s_second().to_be_bytes();
        // s_second.reverse();
        bytes[80..112].copy_from_slice(&s_second[..]);
        bytes
    }

    pub fn from_bytes(data: &[u8; 112]) -> CtOption<Self> {
        let aa = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[0..48]).unwrap())
            .map(G1Projective::from);
        let e_bytes = <[u8; 32]>::try_from(&data[48..80]).unwrap();
        // e_bytes.reverse();
        let ee = Scalar::from_be_bytes(&e_bytes);
        let s_bytes = <[u8; 32]>::try_from(&data[80..112]).unwrap();
        // s_bytes.reverse();
        let ss = Scalar::from_be_bytes(&s_bytes);

        aa.and_then(|a| {
            ee.and_then(|e| ss.and_then(|s| CtOption::new(Self::BBSplus(BBSplusBlindSignature{ a, e, s_second: s }), Choice::from(1))))
        })
    }

}