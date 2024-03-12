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
use crate::{bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, errors::Error, schemes::{algorithms::BBSplus, generics::{BlindSignature, Commitment, Signature, ZKPoK}}, utils::{message::BBSplusMessage, util::bbsplus_utils::{calculate_domain, calculate_domain_new, hash_to_scalar_new, hash_to_scalar_old, ScalarExt}}};
use super::{commitment::BBSplusCommitment, keys::{BBSplusSecretKey, BBSplusPublicKey}, signature::BBSplusSignature};



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusBlindSignature {
    pub(crate) A: G1Projective,
    pub(crate) e: Scalar,
}

impl BBSplusBlindSignature {
    pub const BYTES: usize = G1Projective::COMPRESSED_BYTES + Scalar::BYTES;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; Self::BYTES];
        bytes[0..G1Projective::COMPRESSED_BYTES].copy_from_slice(&self.A.to_affine().to_compressed());
        let e = self.e.to_be_bytes();
        bytes[G1Projective::COMPRESSED_BYTES..Self::BYTES].copy_from_slice(&e[..]);
        bytes
    }

    pub fn from_bytes(data: &[u8; Self::BYTES]) -> Result<Self, Error> {
        let A_opt = G1Affine::from_compressed(&<[u8; G1Projective::COMPRESSED_BYTES]>::try_from(&data[0..G1Projective::COMPRESSED_BYTES]).unwrap())
            .map(G1Projective::from);

        if A_opt.is_none().into() {
            return Err(Error::DeserializationError("Invalid blind signature".to_owned()));
        }
        let A: G1Projective = A_opt.unwrap();

        let e_bytes = <[u8; Scalar::BYTES]>::try_from(&data[G1Projective::COMPRESSED_BYTES..Self::BYTES]).unwrap();
        let e_opt = Scalar::from_be_bytes(&e_bytes);

        if e_opt.is_none().into() {
            return Err(Error::DeserializationError("Invalid signature".to_owned()));
        }
        let e = e_opt.unwrap();


        Ok(Self{A, e})
    }
}


impl <CS:BbsCiphersuite> BlindSignature<BBSplus<CS>> {

    pub fn blind_sign(sk: &BBSplusSecretKey, pk: &BBSplusPublicKey, commitment_with_proof: Option<&[u8]>, header: Option<&[u8]>, messages: Option<&[Vec<u8>]>, signer_blind: Option<Scalar>) -> Result<Self, Error>{
        let messages = messages.unwrap_or(&[]);
        let L = messages.len();
        let commitment_with_proof = commitment_with_proof.unwrap_or(&[]);
        let mut M = commitment_with_proof.len();
        if M != 0 {
            M = M.checked_sub(G1Projective::COMPRESSED_BYTES).ok_or(Error::InvalidCommitmentProof)?;
            M = M.checked_sub(Scalar::BYTES).ok_or(Error::InvalidCommitmentProof)?;
            M = M.checked_div(Scalar::BYTES).ok_or(Error::InvalidCommitmentProof)?;
        }

        let generators = Generators::create::<CS>(M + L + 1, Some(CS::API_ID_BLIND));

        let message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID_BLIND)?;

        let blind_sig = core_blind_sign::<CS>(sk,
            pk,
            &generators,
            commitment_with_proof,
            header,
            &message_scalars,
            signer_blind,
            Some(CS::API_ID_BLIND)
        )?;

        Ok(Self::BBSplus(blind_sig))

    }

    pub fn A(&self) -> G1Projective {
        match self {
            Self::BBSplus(inner) => inner.A,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn e(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.e,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn bbsPlusBlindSignature(&self) -> &BBSplusBlindSignature{
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn to_bytes(&self) -> [u8; BBSplusBlindSignature::BYTES] {
        self.bbsPlusBlindSignature().to_bytes()
    }

    pub fn from_bytes(data: &[u8; BBSplusBlindSignature::BYTES]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusBlindSignature::from_bytes(data)?))
    }

}



fn core_blind_sign<CS>(
        sk: &BBSplusSecretKey,
        pk: &BBSplusPublicKey,
        generators: &Generators,
        commitment_with_proof: &[u8],
        header: Option<&[u8]>,
        messages: &[BBSplusMessage],
        signer_blind: Option<Scalar>,
        api_id: Option<&[u8]>) -> Result<BBSplusBlindSignature, Error>
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let api_id = api_id.unwrap_or(b"");
        let signature_dst = [api_id, CS::H2S].concat();
        let L = messages.len();

        let (mut commit, M) = Commitment::<BBSplus<CS>>::deserialize_and_validate_commit(Some(commitment_with_proof), generators, Some(api_id))?;
        let Q1 = generators.values[0];

        let Q2 = if commit.is_identity().into() && M == 0 {
            G1Projective::IDENTITY
        } else {
            generators.values[1]
        };

        let signer_blind = signer_blind.unwrap_or(Scalar::ZERO);

        let H_points = &generators.values[M+1..M+L+1]; //TODO: to check

        let domain = calculate_domain_new::<CS>(pk, Q1, H_points, header, Some(api_id))?;

        let mut e_octs: Vec<u8> = Vec::new();
        e_octs.extend_from_slice(&sk.to_bytes());
        e_octs.extend_from_slice(&domain.to_bytes_be());
        messages.iter().map(|&p| p.value.to_bytes_be()).for_each(|a| e_octs.extend_from_slice(&a));
        e_octs.extend_from_slice(&signer_blind.to_bytes_be());
        e_octs.extend_from_slice(commitment_with_proof);

        let e = hash_to_scalar_new::<CS>(&e_octs, &signature_dst)?;
        commit += Q2 * signer_blind;

        let mut B = generators.g1_base_point + Q1 * domain;

        for i in 0..L {
            B += H_points[i] * messages[i].value;
        }

        B += commit;

        let sk_e = sk.0 + e;
        let A = B * sk_e.invert().unwrap();


        Ok(BBSplusBlindSignature{A, e})
    }