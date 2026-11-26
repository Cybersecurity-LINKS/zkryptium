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
    keys::{CL03PublicKey, CL03SecretKey},
    proof::CL03TrustedCommitment,
    signature::CL03Signature,
};
use crate::{
    cl03::{bases::Bases, ciphersuites::CLCiphersuite},
    errors::Error,
    schemes::algorithms::CL03,
    schemes::generics::{BlindSignature, Commitment, Signature, ZKPoK},
    utils::message::cl03_message::CL03Message,
    utils::random::{random_bits, random_prime},
};
use digest::Digest;
use rug::{ops::Pow, Integer};
use serde::{Deserialize, Serialize};
use std::panic;

/// Messages disclosed to the Signer, with their indexes in the full list of messages. The two
/// slices must have the same length; every index must be a valid index of the bases.
#[derive(Clone, Copy, Debug)]
pub struct CL03RevealedMessages<'a> {
    /// The revealed messages.
    pub messages: &'a [CL03Message],
    /// The index of each revealed message.
    pub indexes: &'a [usize],
}

/// Optional inputs of [`BlindSignature::blind_sign`]. Both default to none.
#[derive(Clone, Copy, Debug, Default)]
pub struct CL03BlindSignInput<'a> {
    /// When set, the ZKPoK must also prove that the commitment hides the same secrets as
    /// this trusted party commitment.
    pub trusted_commitment: Option<CL03TrustedCommitment<'a>>,
    /// Messages known to the Signer, added to the commitment before signing.
    pub revealed: Option<CL03RevealedMessages<'a>>,
}

/// Returns `C` extended with the revealed messages, after checking that they are consistent
/// with the bases (the extension itself panics on inconsistent input).
fn extend_with_revealed<CS: CLCiphersuite>(
    C: &CL03Commitment,
    revealed: Option<CL03RevealedMessages<'_>>,
    pk: &CL03PublicKey,
    a_bases: &Bases,
) -> Result<Commitment<CL03<CS>>, String> {
    let mut extended_commitment: Commitment<CL03<CS>> = Commitment::CL03(C.clone());
    if let Some(revealed) = revealed {
        if revealed.messages.len() != revealed.indexes.len() {
            return Err("revealed messages and indexes have different lengths".to_owned());
        }
        if revealed.indexes.iter().any(|&i| i >= a_bases.0.len()) {
            return Err("revealed message index out of range of the bases".to_owned());
        }
        if !revealed.messages.iter().all(|m| m.is_in_range::<CS>()) {
            return Err("revealed message outside [0, 2^lm)".to_owned());
        }
        extended_commitment.extend_commitment_with_pk(
            revealed.messages,
            pk,
            a_bases,
            Some(revealed.indexes),
        );
    }
    Ok(extended_commitment)
}

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

    /// Signs the commitment `C` after verifying the Prover ZKPoK of the committed secrets.
    ///
    /// # Errors
    /// [`Error::BlindSignError`] if the ZKPoK is not valid, or if `input.revealed` has
    /// messages and indexes of different lengths or an index outside `a_bases`.
    pub fn blind_sign(
        pk: &CL03PublicKey,
        sk: &CL03SecretKey,
        a_bases: &Bases,
        zkpok: &ZKPoK<CL03<CS>>,
        C: &CL03Commitment,
        unrevealed_message_indexes: &[usize],
        input: CL03BlindSignInput<'_>,
    ) -> Result<Self, Error>
    where
        CS::HashAlg: Digest,
    {
        if !zkpok.verify_proof(
            C,
            input.trusted_commitment,
            pk,
            a_bases,
            unrevealed_message_indexes,
        ) {
            return Err(Error::BlindSignError(
                "knowledge of committed secrets not verified".to_owned(),
            ));
        }

        let extended_commitment =
            extend_with_revealed::<CS>(C, input.revealed, pk, a_bases).map_err(Error::BlindSignError)?;
        let mut e = random_prime(CS::le);
        let phi_n = (&sk.p - Integer::from(1)) * (&sk.q - Integer::from(1));
        while !((e > Integer::from(2).pow(CS::le - 1))
            && (e < Integer::from(2).pow(CS::le)) && (Integer::from(e.gcd_ref(&phi_n)) == 1))
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

        Ok(Self::CL03(sig))
    }

    pub fn unblind_sign(&self, commitment: &Commitment<CL03<CS>>) -> Signature<CL03<CS>> {
        let s = commitment.randomness().clone() + self.rprime();
        Signature::CL03(CL03Signature {
            e: self.e().clone(),
            s,
            v: self.v().clone(),
        })
    }

    /// Re-signs the commitment `C` extended with new values of the revealed messages, keeping
    /// `e` and `rprime`.
    ///
    /// # Errors
    /// [`Error::UpdateSignatureError`] if `revealed` has messages and indexes of different
    /// lengths or an index outside `a_bases`.
    pub fn update_signature(
        &self,
        C: &CL03Commitment,
        sk: &CL03SecretKey,
        pk: &CL03PublicKey,
        a_bases: &Bases,
        revealed: Option<CL03RevealedMessages<'_>>,
    ) -> Result<Self, Error> {
        let extended_commitment = extend_with_revealed::<CS>(C, revealed, pk, a_bases)
            .map_err(Error::UpdateSignatureError)?;

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
        Ok(Self::CL03(sig))
    }
}

#[cfg(test)]
mod tests;
