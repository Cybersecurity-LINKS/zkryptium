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

use std::marker::PhantomData;

use bls12_381_plus::{G1Projective, Scalar, G1Affine, G2Projective, Gt, multi_miller_loop, G2Prepared};
use ff::Field;
use rug::{Integer, ops::Pow, integer::Order};
use serde::{Deserialize, Serialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, utils::message::{CL03Message, BBSplusMessage}, bbsplus::{ciphersuites::BbsCiphersuite, generators::{Generators, self, signer_specific_generators, make_generators}}, cl03::{ciphersuites::CLCiphersuite, bases::Bases}, utils::{random::{random_prime, random_bits}, util::{calculate_domain, serialize, hash_to_scalar_old}}, schemes::generics::Signature};

use elliptic_curve::{hash2curve::ExpandMsg, group::Curve, subtle::{CtOption, Choice}};

use super::keys::{CL03PublicKey, CL03SecretKey};



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03Signature {
    pub(crate) e: Integer,
    pub(crate) s: Integer,
    pub(crate) v: Integer,
}



impl <CS: CLCiphersuite> Signature<CL03<CS>> {

    pub fn sign(pk: &CL03PublicKey, sk: &CL03SecretKey, a_bases: &Bases, message: &CL03Message) -> Self {
        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));

        while ((&e > &Integer::from(2).pow(CS::le-1)) && (&e < &Integer::from(2).pow(CS::le)) && (Integer::from(e.gcd_ref(&phi_n)) == 1)) == false {
            e = random_prime(CS::le);
        }

        let s = random_bits(CS::ls);
        let e2n = Integer::from(e.invert_ref(&phi_n).unwrap());
        // v = powmod((powmod(pk['a0'], m, pk['N']) * powmod(pk['b'], s, pk['N']) * pk['c']), (e2n), pk['N'])
        let v = ((Integer::from(a_bases.0[0].pow_mod_ref(&message.value, &pk.N).unwrap())) * Integer::from(pk.b.pow_mod_ref(&s, &pk.N).unwrap()) * &pk.c).pow_mod(&e2n, &pk.N).unwrap();
        
        let sig = CL03Signature{e, s, v};
        Self::CL03(sig)
    }

    //TODO: tenere solo verify_multiattr visto che funzione anche con un solo messaggio?
    pub fn verify(&self, pk: &CL03PublicKey, a_bases: &Bases, message: &CL03Message) -> bool {

        let sign = self.cl03Signature();

        let lhs = Integer::from(sign.v.pow_mod_ref(&sign.e,&pk.N).unwrap());

        let rhs = (Integer::from(a_bases.0[0].pow_mod_ref(&message.value, &pk.N).unwrap()) * Integer::from(pk.b.pow_mod_ref(&sign.s, &pk.N).unwrap()) * &pk.c) % &pk.N;

        if sign.e <= Integer::from(2).pow(CS::le-1) || sign.e >= Integer::from(2).pow(CS::le) {
            return false
        }

        if lhs == rhs {
            return true
        }

        false
    }

    pub fn verify_multiattr(&self, pk: &CL03PublicKey, a_bases: &Bases, messages: &[CL03Message]) -> bool{
        if messages.len() > a_bases.0.len() {
            panic!("Not enought a_bases!");
        }

        let sign = self.cl03Signature();

        let lhs = Integer::from(sign.v.pow_mod_ref(&sign.e,&pk.N).unwrap());

        let mut rhs = Integer::from(1);

        messages.iter().enumerate().for_each(|(i,m)| rhs = &rhs * Integer::from(a_bases.0[i].pow_mod_ref(&m.value, &pk.N).unwrap()) );

        rhs = (&rhs * Integer::from(pk.b.pow_mod_ref(&sign.s, &pk.N).unwrap()) * &pk.c) % &pk.N;

        if sign.e <= Integer::from(2).pow(CS::le -1) {
            return false;
        }

        if lhs == rhs {
            return true;
        }

        false
    }

    pub fn cl03Signature(&self) -> &CL03Signature{
        match self {
            Self::CL03(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8>{
        let signature = self.cl03Signature();
        let mut bytes: Vec<u8> = Vec::new();
        let mut e_digits = vec!(0u8; CS::le as usize);
        let mut s_digits = vec!(0u8; CS::ls as usize);
        signature.e.write_digits(&mut e_digits, Order::MsfBe);
        signature.s.write_digits(&mut s_digits, Order::MsfBe);
        bytes.extend_from_slice(&e_digits);
        bytes.extend_from_slice(&s_digits);
        bytes.extend_from_slice(&signature.v.to_digits(Order::MsfBe));

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let e = Integer::from_digits(&bytes[0usize .. CS::le as usize], Order::MsfBe);
        let s = Integer::from_digits(&bytes[CS::le as usize .. (CS::le as usize + CS::ls as usize)], Order::MsfBe);
        let v = Integer::from_digits(&bytes[(CS::le as usize + CS::ls as usize) ..], Order::MsfBe);

        Self::CL03(CL03Signature { e, s, v })
    }
}

