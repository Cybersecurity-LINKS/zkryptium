// SPDX-FileCopyrightText: 2023 Fondazione LINKS
//
// SPDX-License-Identifier: APACHE-2.0


use std::panic;

use bls12_381_plus::{G1Projective, Scalar, G1Affine};
use digest::Digest;
use elliptic_curve::{group::Curve, subtle::{CtOption, Choice}, hash2curve::ExpandMsg};
use rug::{Integer, ops::Pow};
use serde::{Deserialize, Serialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, utils::message::{BBSplusMessage, CL03Message}, bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, cl03::ciphersuites::CLCiphersuite, keys::{cl03_key::{CL03PublicKey, CL03SecretKey, CL03CommitmentPublicKey}, bbsplus_key::{BBSplusSecretKey, BBSplusPublicKey}}, utils::{random::{random_prime, random_bits}, util::{calculate_domain, ScalarExt, hash_to_scalar_old}}, errors::BlindSignError};

use super::{commitment::{CL03Commitment, Commitment, BBSplusCommitment}, signature::{CL03Signature, BBSplusSignature, Signature}, proof::ZKPoK};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusBlindSignature {
    pub(crate) a: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s_second: Scalar,
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03BlindSignature {
    pub(crate) e: Integer,
    pub(crate) rprime: Integer,
    pub(crate) v: Integer,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum BlindSignature<S: Scheme> {
    BBSplus(BBSplusBlindSignature),
    CL03(CL03BlindSignature),
    _Unreachable(std::marker::PhantomData<S>)
}

impl <CS:BbsCiphersuite> BlindSignature<BBSplus<CS>> {

    pub fn blind_sign(revealed_messages: &[BBSplusMessage], commitment: &BBSplusCommitment, zkpok: &ZKPoK<BBSplus<CS>>, sk: &BBSplusSecretKey, pk: &BBSplusPublicKey, generators: &Generators, revealed_message_indexes: &[usize], unrevealed_message_indexes: &[usize], nonce: &[u8], header: Option<&[u8]>) -> Result<Self, Box<BlindSignError>>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
            let K = revealed_message_indexes.len();
            if revealed_messages.len() != K {
                return Err(Box::new(BlindSignError(
                    "len(known_messages) != len(revealed_message_indexes)".to_string(),
                )));
            }

            let header = header.unwrap_or(b"");

            let U = unrevealed_message_indexes.len();
            let L = K + U;

            let domain = calculate_domain::<CS>(pk, generators.q1, generators.q2, &generators.message_generators[0..L], Some(header));
            
            let mut e_s_for_hash: Vec<u8> = Vec::new();
            e_s_for_hash.extend_from_slice(&sk.0.to_bytes_be());
            e_s_for_hash.extend_from_slice(&domain.to_bytes_be());
            revealed_messages.iter().for_each(|m| e_s_for_hash.extend_from_slice(&m.value.to_bytes_be()));
            // e = HASH(PRF(8 \* ceil(log2(r)))) mod r
            // s'' = HASH(PRF(8 \* ceil(log2(r)))) mod r
            let e_s = hash_to_scalar_old::<CS>(&e_s_for_hash, 2, None);
            let e = e_s[0];
            let s_second = e_s[1];

            // if BlindMessagesProofVerify(commitment, nizk, CGIdxs, nonce) is INVALID abort
            if !zkpok.verify_proof(commitment, generators, unrevealed_message_indexes, nonce){
                return Err(Box::new(BlindSignError(
                    "Knowledge of committed secrets not verified".to_string(),
                )));
            }

            for i in revealed_message_indexes {
                if unrevealed_message_indexes.contains(i) {
                    return Err(Box::new(BlindSignError(
                        "revealed_message_indexes in unrevealed_message_indexes".to_string(),
                    )));
                }
            }

            // b = commitment + P1 + h0 * s'' + h[j1] * msg[1] + ... + h[jK] * msg[K]
            let mut B = commitment.value + generators.g1_base_point + generators.q1 * s_second + generators.q2 * domain;

            for j in 0..K {
                B += generators.message_generators.get(revealed_message_indexes[j]).expect("index overflow") * revealed_messages.get(j).expect("index overflow").value;
            }

            let SK_plus_e = sk.0 + e;

            let A = B * SK_plus_e.invert().unwrap();

            if A == G1Projective::IDENTITY{
                return Err(Box::new(BlindSignError("A == IDENTITY G1".to_string())));
            }
            Ok(Self::BBSplus(BBSplusBlindSignature{a: A, e, s_second}))

    }

    pub fn unblind_sign(&self, commitment: &BBSplusCommitment) -> Signature<BBSplus<CS>> {
        let s = commitment.s_prime + self.s_second();

        Signature::<BBSplus<CS>>::BBSplus(BBSplusSignature{ a: self.a(), e: self.e(), s: s })
    }

    pub fn update_signature(&self, sk: &BBSplusSecretKey, generators: &Generators, old_messages: &[BBSplusMessage], new_message: &BBSplusMessage, update_index: usize) -> Self {

        if generators.message_generators.len() <= update_index  && old_messages.len() <= update_index{
            panic!("len(generators) <= update_index");
        }
        let H_i = generators.message_generators.get(update_index).expect("index overflow");
        let SK_plus_e = sk.0 + self.e();
        let mut B = self.a() * SK_plus_e;
        B = B + (-H_i * old_messages.get(update_index).expect("index overflow").value);
        B = B + (H_i * new_message.value);
        let A = B * SK_plus_e.invert().unwrap();

        if A == G1Projective::IDENTITY{
            panic!("A == IDENTITY G1");
        }

        return Self::BBSplus(BBSplusBlindSignature { a: A, e: self.e(), s_second: self.s_second() })
    }

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

    pub fn blind_sign(pk: &CL03PublicKey, sk: &CL03SecretKey, zkpok: &ZKPoK<CL03<CS>>, revealed_messages: Option<&[CL03Message]>, C: &CL03Commitment, C_trusted: Option<&CL03Commitment>, commitment_pk: Option<&CL03CommitmentPublicKey>, unrevealed_message_indexes: &[usize], revealed_message_indexes: Option<&[usize]>) -> Self
    where
        CS::HashAlg: Digest
    {

        if !zkpok.verify_proof(C, C_trusted, pk, commitment_pk, unrevealed_message_indexes) {
            panic!("Knowledge of committed secrets not verified");
        }

        let mut extended_commitment: Commitment<CL03<CS>> = Commitment::CL03(C.clone());
        if revealed_messages.is_some() && revealed_message_indexes.is_some() { 
            extended_commitment.extend_commitment_with_pk(revealed_messages.unwrap(), pk, revealed_message_indexes);
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

    pub fn update_signature(&self, revealed_messages: Option<&[CL03Message]>, C: &CL03Commitment, sk: &CL03SecretKey, pk: &CL03PublicKey,  revealed_message_indexes: Option<&[usize]>) -> Self {
        let mut extended_commitment: Commitment<CL03<CS>> = Commitment::CL03(C.clone());
        if revealed_messages.is_some() && revealed_message_indexes.is_some() { 
            extended_commitment.extend_commitment_with_pk(revealed_messages.unwrap(), pk, revealed_message_indexes);
        }

        let phi_N = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));
        let e2n = Integer::from(self.e().invert_ref(&phi_N).unwrap());

        let v = Integer::from((extended_commitment.value() * Integer::from(pk.b.pow_mod_ref(self.rprime(), &pk.N).unwrap()) * &pk.c).pow_mod_ref(&e2n, &pk.N).unwrap());
    
        let sig = CL03BlindSignature{e: self.e().clone(), rprime: self.rprime().clone(), v};
        Self::CL03(sig)
    }
}