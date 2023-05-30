use core::result::Result;
use std::marker::PhantomData;

use bls12_381_plus::{G1Projective, Scalar};
use rug::{Integer, ops::Pow};
use serde::{Deserialize, Serialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, bbsplus::{ciphersuites::BbsCiphersuite, message::CL03Message}, cl03::ciphersuites::CLCiphersuite, utils::random::{random_prime, random_bits}, keys::cl03_key::{CL03PublicKey, CL03SecretKey}};



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

    pub fn sign() -> Self {
        todo!()
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

