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

use super::keys::{CL03PublicKey, CL03SecretKey};
use crate::{
    cl03::{bases::Bases, ciphersuites::CLCiphersuite},
    schemes::algorithms::CL03,
    schemes::generics::Signature,
    utils::message::cl03_message::CL03Message,
    utils::random::{random_bits, random_prime},
};
use rug::{integer::Order, ops::Pow, Integer};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03Signature {
    pub(crate) e: Integer,
    pub(crate) s: Integer,
    pub(crate) v: Integer,
}

impl<CS: CLCiphersuite> Signature<CL03<CS>> {
    pub fn sign(
        pk: &CL03PublicKey,
        sk: &CL03SecretKey,
        a_bases: &Bases,
        message: &CL03Message,
    ) -> Self {
        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));

        while ((&e > &Integer::from(2).pow(CS::le - 1))
            && (&e < &Integer::from(2).pow(CS::le))
            && (Integer::from(e.gcd_ref(&phi_n)) == 1))
            == false
        {
            e = random_prime(CS::le);
        }

        let s = random_bits(CS::ls);
        let e2n = Integer::from(e.invert_ref(&phi_n).unwrap());
        // v = powmod((powmod(pk['a0'], m, pk['N']) * powmod(pk['b'], s, pk['N']) * pk['c']), (e2n), pk['N'])
        let v = ((Integer::from(a_bases.0[0].pow_mod_ref(&message.value, &pk.N).unwrap()))
            * Integer::from(pk.b.pow_mod_ref(&s, &pk.N).unwrap())
            * &pk.c)
            .pow_mod(&e2n, &pk.N)
            .unwrap();

        let sig = CL03Signature { e, s, v };
        Self::CL03(sig)
    }

    pub fn sign_multiattr(
        pk: &CL03PublicKey,
        sk: &CL03SecretKey,
        a_bases: &Bases,
        messages: &[CL03Message],
    ) -> Self {
        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));

        while ((&e > &Integer::from(2).pow(CS::le - 1))
            && (&e < &Integer::from(2).pow(CS::le))
            && (Integer::from(e.gcd_ref(&phi_n)) == 1))
            == false
        {
            e = random_prime(CS::le);
        }

        let s = random_bits(CS::ls);
        let e2n = Integer::from(e.invert_ref(&phi_n).unwrap());
        // v = powmod((powmod(pk['a0'], m, pk['N']) * powmod(pk['b'], s, pk['N']) * pk['c']), (e2n), pk['N'])
        let mut v: Integer = Integer::from(1);
        for (index, message) in messages.iter().enumerate() {
            v = v * Integer::from(a_bases.0[index].pow_mod_ref(&message.value, &pk.N).unwrap())
        }
        v = (v * Integer::from(pk.b.pow_mod_ref(&s, &pk.N).unwrap()) * &pk.c)
            .pow_mod(&e2n, &pk.N)
            .unwrap();

        let sig = CL03Signature { e, s, v };
        Self::CL03(sig)
    }

    //TODO: tenere solo verify_multiattr visto che funziona anche con un solo messaggio?
    pub fn verify(&self, pk: &CL03PublicKey, a_bases: &Bases, message: &CL03Message) -> bool {
        let sign = self.cl03Signature();

        let lhs = Integer::from(sign.v.pow_mod_ref(&sign.e, &pk.N).unwrap());

        let rhs = (Integer::from(a_bases.0[0].pow_mod_ref(&message.value, &pk.N).unwrap())
            * Integer::from(pk.b.pow_mod_ref(&sign.s, &pk.N).unwrap())
            * &pk.c)
            % &pk.N;

        if sign.e <= Integer::from(2).pow(CS::le - 1) || sign.e >= Integer::from(2).pow(CS::le) {
            return false;
        }

        if lhs == rhs {
            return true;
        }

        false
    }

    pub fn verify_multiattr(
        &self,
        pk: &CL03PublicKey,
        a_bases: &Bases,
        messages: &[CL03Message],
    ) -> bool {
        if messages.len() > a_bases.0.len() {
            panic!("Not enought a_bases!");
        }

        let sign = self.cl03Signature();

        let lhs = Integer::from(sign.v.pow_mod_ref(&sign.e, &pk.N).unwrap());

        let mut rhs = Integer::from(1);

        messages.iter().enumerate().for_each(|(i, m)| {
            rhs = &rhs * Integer::from(a_bases.0[i].pow_mod_ref(&m.value, &pk.N).unwrap())
        });

        rhs = (&rhs * Integer::from(pk.b.pow_mod_ref(&sign.s, &pk.N).unwrap()) * &pk.c) % &pk.N;

        if sign.e <= Integer::from(2).pow(CS::le - 1) {
            return false;
        }

        if lhs == rhs {
            return true;
        }

        false
    }

    pub fn disclose_selectively(&self, messages: &[CL03Message], a_bases: Bases, pk: &CL03PublicKey, unrevealed_indexes: &[usize]) -> (Vec<CL03Message>, Bases) {

        if messages.len() != a_bases.0.len() {
            panic!("Mismatch between messages and bases length!");
        }

        let mut sd_messages: Vec<CL03Message> = Vec::from(messages);

        if unrevealed_indexes.len() == 0 {
            return (sd_messages, a_bases)
        }

        let mut sd_bases: Bases = a_bases.clone();

        for index in unrevealed_indexes {
            sd_bases.0[*index] = Integer::from(a_bases.0[*index].pow_mod_ref(&messages[*index].value, &pk.N).unwrap());
            sd_messages[*index].value = Integer::from(1);
        }

        (sd_messages, sd_bases)
    }

    pub fn cl03Signature(&self) -> &CL03Signature {
        match self {
            Self::CL03(inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let signature = self.cl03Signature();
        let mut bytes: Vec<u8> = Vec::new();
        let mut e_digits = vec![0u8; CS::le as usize];
        let mut s_digits = vec![0u8; CS::ls as usize];
        signature.e.write_digits(&mut e_digits, Order::MsfBe);
        signature.s.write_digits(&mut s_digits, Order::MsfBe);
        bytes.extend_from_slice(&e_digits);
        bytes.extend_from_slice(&s_digits);
        bytes.extend_from_slice(&signature.v.to_digits(Order::MsfBe));

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let e = Integer::from_digits(&bytes[0usize..CS::le as usize], Order::MsfBe);
        let s = Integer::from_digits(
            &bytes[CS::le as usize..(CS::le as usize + CS::ls as usize)],
            Order::MsfBe,
        );
        let v = Integer::from_digits(&bytes[(CS::le as usize + CS::ls as usize)..], Order::MsfBe);

        Self::CL03(CL03Signature { e, s, v })
    }
}

#[cfg(test)]
mod tests {

    use crate::cl03::ciphersuites::{CLCiphersuite};
    use crate::schemes::algorithms::{CL03_CL1024_SHA256, CL03_CL2048_SHA256, CL03_CL3072_SHA256};
    use crate::{
        cl03::bases::Bases,
        keys::pair::KeyPair,
        schemes::algorithms::{Ciphersuite, Scheme, CL03},
        schemes::generics::Signature,
        utils::message::cl03_message::CL03Message,
    };
    use digest::Digest;

    //Signature (sign) - CL1024-SHA256
    #[test]
    fn signature_cl1024_sha256() {
        signature::<CL03_CL1024_SHA256>();
    }

    #[test]
    fn signature_cl2048_sha256() {
        signature::<CL03_CL2048_SHA256>();
    }

    #[test]
    fn signature_cl3072_sha256() {
        signature::<CL03_CL3072_SHA256>();
    }

    #[test]
    fn keypair_cl1024_sha256() {
        keypair::<CL03_CL1024_SHA256>();
    }

    #[test]
    fn keypair_cl2048_sha256() {
        keypair::<CL03_CL2048_SHA256>();
    }

    #[test]
    fn keypair_cl3072_sha256() {
        keypair::<CL03_CL3072_SHA256>();
    }

    fn keypair<S: Scheme>()
    where
        S::Ciphersuite: CLCiphersuite,
        <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
    {
         KeyPair::<CL03<S::Ciphersuite>>::generate();
    }

    fn signature<S: Scheme>()
    where
        S::Ciphersuite: CLCiphersuite,
        <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
    {
        const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
        const wrong_msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03";

        let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
        let a_bases = Bases::generate(cl03_keypair.public_key(), 1);

        let message = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
            &hex::decode(msg).unwrap(),
        );

        let wrong_message = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
            &hex::decode(wrong_msg).unwrap(),
        );

        let signature = Signature::<CL03<S::Ciphersuite>>::sign(
            cl03_keypair.public_key(),
            cl03_keypair.private_key(),
            &a_bases,
            &message,
        );

        let valid = signature.verify(cl03_keypair.public_key(), &a_bases, &message);

        assert!(valid, "Error! Signature should be VALID");

        let valid = signature.verify(cl03_keypair.public_key(), &a_bases, &wrong_message);

        assert!(!valid, "Error! Signature should be INVALID");
    }
}
