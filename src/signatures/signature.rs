use core::result::Result;
use std::marker::PhantomData;

use bls12_381_plus::{G1Projective, Scalar};
use rug::{Integer, ops::Pow};
use serde::{Deserialize, Serialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, bbsplus::{ciphersuites::BbsCiphersuite, message::{CL03Message, BBSplusMessage, Message}, generators::Generators}, cl03::ciphersuites::CLCiphersuite, utils::{random::{random_prime, random_bits}, util::{calculate_domain, hash_to_scalar}}, keys::{cl03_key::{CL03PublicKey, CL03SecretKey}, bbsplus_key::{BBSplusSecretKey, BBSplusPublicKey}}};

use super::commitment::BBSplusCommitment;
use elliptic_curve::hash2curve::{ExpandMsg, Expander};



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusSignature {
    pub(crate) a: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03Signature {
    pub(crate) e: Integer,
    pub(crate) s: Integer,
    pub(crate) v: Integer,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Signature<S: Scheme> {
    BBSplus(BBSplusSignature),
    CL03(CL03Signature),
    _Unreachable(std::marker::PhantomData<S>)
}


impl <CS: BbsCiphersuite> Signature<BBSplus<CS>> {

    pub fn sign(messages: Option<&[BBSplusMessage]>, sk: &BBSplusSecretKey, pk: &BBSplusPublicKey, generators: &Generators, header: Option<&[u8]>) -> Self {
        let header = header.unwrap_or(b"");

        let messages = messages.unwrap_or(&[]);

        let L = messages.len();

        if generators.message_generators.len() < L {
            panic!("not enough generators!");
        }

        let domain = calculate_domain(pk, generators.q1, generators.q2, &generators.message_generators, Some(header));
        let e_s_for_hash: Vec<u8> = Vec::new();
        e_s_for_hash.extend_from_slice(&sk.to_bytes());
        e_s_for_hash.extend_from_slice(&domain.to_bytes());
        messages.iter().map(|m| m.to_bytes()).for_each(|m| e_s_for_hash.extend_from_slice(&m));

        // e_s_len = octet_scalar_length * 2
        // 7.  e_s_expand = expand_message(e_s_octs, expand_dst, e_s_len)
        // 8.  if e_s_expand is INVALID, return INVALID
        // 9.  e = hash_to_scalar(e_s_expand[0..(octet_scalar_length - 1)])
        // 10. s = hash_to_scalar(e_s_expand[octet_scalar_length..(e_s_len - 1)])

        let e_s_len = CS::OCTECT_SCALAR_LEN * 2;


        let mut e_s_expand = vec!(0u8; e_s_len);

        CS::Expander::expand_message(&[&e_s_for_hash], &[CS::GENERATOR_SEED_DST], e_s_len).unwrap().fill_bytes(&mut e_s_expand);

        let e = hash_to_scalar(&e_s_expand[0..(CS::OCTECT_SCALAR_LEN-1)], None);
        let s = hash_to_scalar(&e_s_expand[CS::OCTECT_SCALAR_LEN..(e_s_len-1)], None);



		// # B = P1 + Q_1 * s + Q_2 * domain + H_1 * msg_1 + ... + H_L * msg_L
		// B = P1 + Q_1 * s + Q_2 * domain
		// for i in range(0, L):
		// 	B += H[i] * messages[i]	
		// # Check if (SK + e) = 0 mod r
		// SK_plus_e = (int(SK) + e) % bls12_381.r
		// assert SK_plus_e != 0, "(SK + e) = 0 mod r"	
		// # A = B * (1 / (SK + e) mod r)
		// A = B * int(invert(SK_plus_e, bls12_381.r))
		// # Check if A != Identity_G1
		// assert A != G1Infinity(), "A == Identity_G1"
		// # signature = (A, e, s)		
		// signature = signature_to_octets(A, e, s)		
		// return signature
    }

    pub fn verify() -> bool {
        todo!()
    }
}

impl <CS: CLCiphersuite> Signature<CL03<CS>> {

    pub fn sign(pk: &CL03PublicKey, sk: &CL03SecretKey, message: &CL03Message) -> Self {
        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));
        while ((&e > &Integer::from(2.pow(CS::le-1))) && (&e < &Integer::from(2.pow(CS::le))) && (Integer::from(e.gcd_ref(&phi_n)) == 1)) == false {
            e = random_prime(CS::le.try_into().unwrap());
        }

        let s = random_bits(CS::ls);
        let e2n = Integer::from(e.invert_ref(&phi_n).unwrap());
        // v = powmod((powmod(pk['a0'], m, pk['N']) * powmod(pk['b'], s, pk['N']) * pk['c']), (e2n), pk['N'])
        let v = ((Integer::from(pk.a_bases[0].0.pow_mod_ref(&message.value, &pk.N).unwrap())) * Integer::from(pk.b.pow_mod_ref(&s, &pk.N).unwrap()) * &pk.c).pow_mod(&e2n, &pk.N).unwrap();
        
        let sig = CL03Signature{e, s, v};
        Self::CL03(sig)
    }

    pub fn verify(&self, pk: &CL03PublicKey, message: &CL03Message) -> bool {

        let sign = self.cl03Signature();

        let lhs = Integer::from(sign.v.pow_mod_ref(&sign.e,&pk.N).unwrap());

        let rhs = (Integer::from(pk.a_bases[0].0.pow_mod_ref(&message.value, &pk.N).unwrap()) * Integer::from(pk.b.pow_mod_ref(&sign.s, &pk.N).unwrap()) * &pk.c) % &pk.N;

        if sign.e <= Integer::from(2.pow(CS::le-1)) || sign.e >= Integer::from(2.pow(CS::le)) {
            return false
        }

        if lhs == rhs {
            return true
        }

        false
    }

    pub(crate) fn cl03Signature(&self) -> &CL03Signature{
        match self {
            Self::CL03(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }
}

