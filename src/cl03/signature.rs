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
    errors::Error,
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
    /// Signs one message with the first base.
    ///
    /// # Errors
    /// [`Error::SignatureGenerationError`] if the message is outside `[0, 2^lm)` (see
    /// [`CL03Message::is_in_range`]) or `a_bases` is empty.
    pub fn sign(
        pk: &CL03PublicKey,
        sk: &CL03SecretKey,
        a_bases: &Bases,
        message: &CL03Message,
    ) -> Result<Self, Error> {
        if a_bases.0.is_empty() {
            return Err(Error::SignatureGenerationError("no bases".to_owned()));
        }
        if !message.is_in_range::<CS>() {
            return Err(Error::SignatureGenerationError("message outside [0, 2^lm)".to_owned()));
        }
        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));

        while !((e > Integer::from(2).pow(CS::le - 1))
            && (e < Integer::from(2).pow(CS::le)) && (Integer::from(e.gcd_ref(&phi_n)) == 1))
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
        Ok(Self::CL03(sig))
    }

    /// Signs `messages`, message `i` with base `i`.
    ///
    /// # Errors
    /// [`Error::SignatureGenerationError`] if there are more messages than bases or a message
    /// is outside `[0, 2^lm)` (see [`CL03Message::is_in_range`]).
    pub fn sign_multiattr(
        pk: &CL03PublicKey,
        sk: &CL03SecretKey,
        a_bases: &Bases,
        messages: &[CL03Message],
    ) -> Result<Self, Error> {
        if messages.len() > a_bases.0.len() {
            return Err(Error::SignatureGenerationError("more messages than bases".to_owned()));
        }
        if !messages.iter().all(|m| m.is_in_range::<CS>()) {
            return Err(Error::SignatureGenerationError("message outside [0, 2^lm)".to_owned()));
        }
        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));

        while !((e > Integer::from(2).pow(CS::le - 1))
            && (e < Integer::from(2).pow(CS::le)) && (Integer::from(e.gcd_ref(&phi_n)) == 1))
        {
            e = random_prime(CS::le);
        }

        let s = random_bits(CS::ls);
        let e2n = Integer::from(e.invert_ref(&phi_n).unwrap());
        // v = powmod((powmod(pk['a0'], m, pk['N']) * powmod(pk['b'], s, pk['N']) * pk['c']), (e2n), pk['N'])
        let mut v: Integer = Integer::from(1);
        for (index, message) in messages.iter().enumerate() {
            v *= Integer::from(a_bases.0[index].pow_mod_ref(&message.value, &pk.N).unwrap())
        }
        v = (v * Integer::from(pk.b.pow_mod_ref(&s, &pk.N).unwrap()) * &pk.c)
            .pow_mod(&e2n, &pk.N)
            .unwrap();

        let sig = CL03Signature { e, s, v };
        Ok(Self::CL03(sig))
    }

    //TODO: tenere solo verify_multiattr visto che funziona anche con un solo messaggio?
    pub fn verify(&self, pk: &CL03PublicKey, a_bases: &Bases, message: &CL03Message) -> bool {
        let sign = self.cl03Signature();

        // Check e, v and the message before using them: the signature may come from an
        // untrusted party, and an out-of-range message makes forgeries verify (m + k*e).
        if !Self::valid_e_v(sign, pk) || a_bases.0.is_empty() || !message.is_in_range::<CS>() {
            return false;
        }

        let lhs = Integer::from(sign.v.pow_mod_ref(&sign.e, &pk.N).unwrap());

        let rhs = (Integer::from(a_bases.0[0].pow_mod_ref(&message.value, &pk.N).unwrap())
            * Integer::from(pk.b.pow_mod_ref(&sign.s, &pk.N).unwrap())
            * &pk.c)
            % &pk.N;

        lhs == rhs
    }

    /// `2^(le-1) < e < 2^le` and `v` is a unit modulo N.
    fn valid_e_v(sign: &CL03Signature, pk: &CL03PublicKey) -> bool {
        sign.e > Integer::from(2).pow(CS::le - 1)
            && sign.e < Integer::from(2).pow(CS::le)
            && crate::utils::util::cl03_utils::is_unit(&sign.v, &pk.N)
    }

    pub fn verify_multiattr(
        &self,
        pk: &CL03PublicKey,
        a_bases: &Bases,
        messages: &[CL03Message],
    ) -> bool {
        // Out-of-range messages make forgeries verify: (e, s, v * a_i^k) is valid on m_i + k*e.
        if messages.len() > a_bases.0.len() || !messages.iter().all(|m| m.is_in_range::<CS>()) {
            return false;
        }

        let sign = self.cl03Signature();
        // Check e and v before using them: the signature may come from an untrusted party.
        if !Self::valid_e_v(sign, pk) {
            return false;
        }

        let lhs = Integer::from(sign.v.pow_mod_ref(&sign.e, &pk.N).unwrap());

        let mut rhs = Integer::from(1);

        messages.iter().enumerate().for_each(|(i, m)| {
            rhs = &rhs * Integer::from(a_bases.0[i].pow_mod_ref(&m.value, &pk.N).unwrap())
        });

        rhs = (&rhs * Integer::from(pk.b.pow_mod_ref(&sign.s, &pk.N).unwrap()) * &pk.c) % &pk.N;

        lhs == rhs
    }

    pub fn disclose_selectively(&self, messages: &[CL03Message], a_bases: Bases, pk: &CL03PublicKey, unrevealed_indexes: &[usize]) -> (Vec<CL03Message>, Bases) {

        if messages.len() != a_bases.0.len() {
            panic!("Mismatch between messages and bases length!");
        }

        let mut sd_messages: Vec<CL03Message> = Vec::from(messages);

        if unrevealed_indexes.is_empty() {
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

    /// Parses the output of [`Self::to_bytes`].
    ///
    /// # Errors
    /// [`Error::InvalidSignature`] if `bytes` is too short to contain `e`, `s` and `v`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() <= CS::le as usize + CS::ls as usize {
            return Err(Error::InvalidSignature);
        }
        let e = Integer::from_digits(&bytes[0usize..CS::le as usize], Order::MsfBe);
        let s = Integer::from_digits(
            &bytes[CS::le as usize..(CS::le as usize + CS::ls as usize)],
            Order::MsfBe,
        );
        let v = Integer::from_digits(&bytes[(CS::le as usize + CS::ls as usize)..], Order::MsfBe);

        Ok(Self::CL03(CL03Signature { e, s, v }))
    }
}

#[cfg(test)]
mod tests;
