// SPDX-FileCopyrightText: 2023 Fondazione LINKS
//
// SPDX-License-Identifier: APACHE-2.0

use std::marker::PhantomData;

use bls12_381_plus::{G1Projective, Scalar, G1Affine, G2Projective, Gt, multi_miller_loop, G2Prepared};
use ff::Field;
use rug::{Integer, ops::Pow, integer::Order};
use serde::{Deserialize, Serialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, utils::message::{CL03Message, BBSplusMessage}, bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, cl03::{ciphersuites::CLCiphersuite, bases::Bases}, utils::{random::{random_prime, random_bits}, util::{calculate_domain, serialize, hash_to_scalar_old}}, keys::{cl03_key::{CL03PublicKey, CL03SecretKey}, bbsplus_key::{BBSplusSecretKey, BBSplusPublicKey}}};

use elliptic_curve::{hash2curve::ExpandMsg, group::Curve, subtle::{CtOption, Choice}};



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
    _Unreachable(PhantomData<S>)
}


impl <CS: BbsCiphersuite> Signature<BBSplus<CS>> {
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

    pub fn s(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.s,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn sign(messages: Option<&[BBSplusMessage]>, sk: &BBSplusSecretKey, pk: &BBSplusPublicKey, generators: &Generators, header: Option<&[u8]>) -> Self 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let header = header.unwrap_or(b"");

        let messages = messages.unwrap_or(&[]);

        let L = messages.len();

        if generators.message_generators.len() < L {
            panic!("not enough generators!");
        }

        let domain = calculate_domain::<CS>(pk, generators.q1, generators.q2, &generators.message_generators, Some(header));

        // let mut e_s_for_hash: Vec<u8> = Vec::new();
        // e_s_for_hash.extend_from_slice(&sk.to_bytes());
        // e_s_for_hash.extend_from_slice(&domain.to_bytes_be());
        // messages.iter().map(|m| m.to_bytes_be()).for_each(|m| e_s_for_hash.extend_from_slice(&m)); //the to_byte_le() may be needed instead

        let mut e_s_for_hash_vec: Vec<Scalar> = Vec::new();
        e_s_for_hash_vec.push(sk.0);
        e_s_for_hash_vec.push(domain);
        messages.iter().for_each(|m| e_s_for_hash_vec.push(m.value)); //the to_byte_le() may be needed instead

        let e_s_for_hash = serialize(&e_s_for_hash_vec);


        //UPDATED from standard (NOT working!)
        // let e_s_len = CS::OCTECT_SCALAR_LEN * 2;
        // let mut e_s_expand = vec!(0u8; e_s_len);
        // CS::Expander::expand_message(&[&e_s_for_hash], &[CS::GENERATOR_SIG_DST], e_s_len).unwrap().fill_bytes(&mut e_s_expand);
        // println!("e_s_exp: {}", hex::encode(e_s_expand.clone()));
        // let e = hash_to_scalar::<CS>(&e_s_expand[0..(CS::OCTECT_SCALAR_LEN-1)], None);
        // let s = hash_to_scalar::<CS>(&e_s_expand[CS::OCTECT_SCALAR_LEN..(e_s_len-1)], None);

        //Old standard
        let scalars = hash_to_scalar_old::<CS>(&e_s_for_hash,2, None);
        let e = scalars[0];
        let s = scalars[1];

        let mut B = generators.g1_base_point + generators.q1 * s + generators.q2 *domain;
        for i in 0..L {
            B = B + generators.message_generators[i] * messages[i].value;
        }

        let SK_plus_e = sk.0 + e;

        if SK_plus_e.is_zero().into() {
            panic!("SK_plus_e == 0")
        }

        let A = B * SK_plus_e.invert().unwrap();
        if A == G1Projective::IDENTITY {
            panic!("A == Identity_G1");
        }

        let signature = BBSplusSignature{a: A, e: e, s: s};

        Self::BBSplus(signature)
    }

    pub fn verify(&self, pk: &BBSplusPublicKey, messages: Option<&[BBSplusMessage]>, generators: &Generators, header: Option<&[u8]>) -> bool 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let header = header.unwrap_or(b"");
        let messages = messages.unwrap_or(&[]);
        let signature = self.bbsPlusSignature();

        let L = messages.len();

        if generators.message_generators.len() < L {
            panic!("not enough generators!");
        }

        let domain = calculate_domain::<CS>(pk, generators.q1, generators.q2, &generators.message_generators, Some(header));

        let mut B = generators.g1_base_point + generators.q1 * signature.s + generators.q2 *domain;

        for i in 0..L {
            B = B + generators.message_generators[i] * messages[i].value;
        }

        let P2 = G2Projective::GENERATOR;
        let A2 = pk.0 + P2 * signature.e;

        let identity_GT = Gt::IDENTITY;

        let Ps = (&signature.a.to_affine(), &G2Prepared::from(A2.to_affine()));
		let Qs = (&B.to_affine(), &G2Prepared::from(-P2.to_affine()));

        let pairing = multi_miller_loop(&[Ps, Qs]).final_exponentiation();

        pairing == identity_GT

    }

    pub fn bbsPlusSignature(&self) -> &BBSplusSignature{
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn to_bytes(&self) -> [u8; 112] {
        let mut bytes = [0u8; 112];
        bytes[0..48].copy_from_slice(&self.a().to_affine().to_compressed());
        let e = self.e().to_be_bytes();
        // e.reverse();
        bytes[48..80].copy_from_slice(&e[..]);
        let s = self.s().to_be_bytes();
        // s.reverse();
        bytes[80..112].copy_from_slice(&s[..]);
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
            ee.and_then(|e| ss.and_then(|s| CtOption::new(Self::BBSplus(BBSplusSignature{ a, e, s }), Choice::from(1))))
        })
    }
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

