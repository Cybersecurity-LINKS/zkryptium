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



use bls12_381_plus::{G1Projective, Scalar, G2Projective, Gt, multi_miller_loop, G2Prepared};
use serde::{Deserialize, Serialize};
use crate::{bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, errors::Error, schemes::{algorithms::BBSplus, generics::Signature}, utils::{message::BBSplusMessage, util::bbsplus_utils::{calculate_domain, hash_to_scalar, parse_g1_projective, serialize, ScalarExt}}};
use elliptic_curve::{hash2curve::ExpandMsg, group::Curve};
use super::keys::{BBSplusPublicKey, BBSplusSecretKey};



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusSignature {
    pub A: G1Projective,
    pub e: Scalar,
}

impl BBSplusSignature {

    pub const BYTES: usize = 80;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; Self::BYTES];
        bytes[0..G1Projective::COMPRESSED_BYTES].copy_from_slice(&self.A.to_affine().to_compressed());
        let e = self.e.to_be_bytes();
        bytes[G1Projective::COMPRESSED_BYTES..Self::BYTES].copy_from_slice(&e);
        bytes
    }

    pub fn from_bytes(data: &[u8; Self::BYTES]) -> Result<Self, Error> {

        let A: G1Projective = parse_g1_projective(&data[0..G1Projective::COMPRESSED_BYTES]).map_err(|_| Error::InvalidSignature)?;
        let e = Scalar::from_bytes_be(&data[G1Projective::COMPRESSED_BYTES..Self::BYTES]).map_err(|_| Error::InvalidSignature)?;

        Ok(Self{A, e})
    }
}



impl <CS: BbsCiphersuite> Signature<BBSplus<CS>> {

    pub fn a(&self) -> G1Projective {
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


    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-signature-generation-sign
    /// # Description
    /// The `sign` API returns a BBS signature from a secret key (SK), over a header and a set of messages.
    /// 
    /// # Inputs:
    /// * `messages` (OPTIONAL), a vector of octet strings representing the messages, it could be an empty vector.
    /// * `sk` (REQUIRED), a secret key 
    /// * `pk` (REQUIRED), a public key
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    /// 
    /// # Output:
    /// * new [`Signature::BBSplus`] or [`Error`]
    pub fn sign(messages: Option<&[Vec<u8>]>, sk: &BBSplusSecretKey, pk: &BBSplusPublicKey, header: Option<&[u8]>) -> Result<Self, Error> 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let messages = messages.unwrap_or(&[]);
        let message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID)?;
        let generators = Generators::create::<CS>(messages.len() + 1, Some(CS::API_ID));
        let signature = core_sign::<CS>(sk, pk, generators, header, &message_scalars, Some(CS::API_ID))?;

        Ok(Self::BBSplus(signature))
    }

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-signature-verification-veri
    /// # Description
    /// The `verify` API validates a BBS signature, given a public key (PK), a header and a set of messages
    /// # Inputs:
    /// * `self`, the signature
    /// * `pk` (REQUIRED), a public key
    /// * `messages` (OPTIONAL), a vector of octet strings representing the messages, it could be an empty vector.
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    /// 
    /// # Output:
    /// * a result either [`Ok()`] or [`Error`]
    pub fn verify(&self, pk: &BBSplusPublicKey, messages: Option<&[Vec<u8>]>, header: Option<&[u8]>) -> Result<(), Error> 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let messages = messages.unwrap_or(&[]);
        let message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID)?;
        let generators = Generators::create::<CS>(messages.len() + 1, Some(CS::API_ID));
        let signature = self.bbsPlusSignature();

        core_verify::<CS>(pk, signature, &message_scalars, generators, header, Some(CS::API_ID))
    }

    pub fn bbsPlusSignature(&self) -> &BBSplusSignature{
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn to_bytes(&self) -> [u8; BBSplusSignature::BYTES] {
        self.bbsPlusSignature().to_bytes()
    }

    pub fn from_bytes(data: &[u8; BBSplusSignature::BYTES]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusSignature::from_bytes(data)?))
    }



    //TODO test update
    /// # Description
    /// Update signature with a new value of a signed message
    /// 
    /// # Inputs:
    /// * `sk` (REQUIRED), Signer private key.
    /// * `old_message` (REQUIRED), message octet string old value.
    /// * `new_message` (REQUIRED), message octet string new value.
    /// * `update_index` (REQUIRED), index of the message to update.
    /// * `n` (REQUIRED), total number of signed messages.
    /// 
    /// # Output:
    /// * new [`BBSplusSignature`] or [`Error`]
    pub fn update_signature(&self, sk: &BBSplusSecretKey, old_message: &[u8], new_message: &[u8], update_index: usize, n: usize) -> Result<Self, Error> {

        let generators  = Generators::create::<CS>(n+1, Some(CS::API_ID));

        if generators.values.len() <= update_index + 1 {
            return Err(Error::UpdateSignatureError("len(generators) <= update_index".to_owned()));
        }
        
        let old_message_scalar = BBSplusMessage::map_message_to_scalar_as_hash::<CS>(old_message, CS::API_ID)?;
        let new_message_scalar = BBSplusMessage::map_message_to_scalar_as_hash::<CS>(new_message, CS::API_ID)?;

        let H_points = &generators.values[1..];
        let H_i = H_points.get(update_index).ok_or(Error::Unspecified)?;
        let sk_e = sk.0 + self.e();
        let mut B = self.a() * sk_e;
        B = B + (-H_i * old_message_scalar.value);
        B = B + (H_i * new_message_scalar.value);

        let sk_e_inv = Option::<Scalar>::from(sk_e.invert()).ok_or(Error::UpdateSignatureError("Invert scalar failed".to_owned()))?;
        let A = B * sk_e_inv;

        if A == G1Projective::IDENTITY{
            return Err(Error::UpdateSignatureError("A == IDENTITY G1".to_owned()));
        }

        return Ok(Self::BBSplus(BBSplusSignature { A, e: self.e() }))
    }
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-coresign
/// # Description
/// This operation computes a deterministic signature from a secret key (SK), a set of generators (points of G1) and optionally a header and a vector of messages.
/// 
/// # Inputs:
/// * `sk` (REQUIRED), a secret key 
/// * `pk` (REQUIRED), a public key
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application specific information.
/// * `messages` (REQUIRED), a vector of scalars (`BBSplusMessage`) representing the messages, it could be an empty vector.
/// * `api_id` (OPTIONAL), an octet string. If not supplied it defaults to theempty octet string ("").
/// 
/// # Output:
/// * new [`BBSplusSignature`] or [`Error`]
fn core_sign<CS>(sk: &BBSplusSecretKey, pk: &BBSplusPublicKey, generators: Generators, header: Option<&[u8]>, messages: &[BBSplusMessage], api_id: Option<&[u8]>) -> Result<BBSplusSignature, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{

    let L = messages.len();

    if generators.values.len() != L+1 {
        return Err(Error::NotEnoughGenerators);
    }

    let Q1 = generators.values[0];
    let H_points = &generators.values[1..];

    let api_id = api_id.unwrap_or(b"");

    let signature_dst = [api_id, CS::H2S].concat();

    let domain = calculate_domain::<CS>(pk, Q1, H_points, header, Some(api_id))?;

    //serialize 
    let mut input: Vec<Scalar> = Vec::new();
    input.push(sk.0);
    input.push(domain);
    messages.iter().for_each(|m| input.push(m.value)); //the to_byte_le() may be needed instead

    let e = hash_to_scalar::<CS>(&serialize(&input), &signature_dst)?;

    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L

    let mut B = generators.g1_base_point + Q1 * domain;

    for i in 0..L {
        B = B + H_points[i] * messages[i].value;
    }

    // A = B * (1 / (SK + e))
    let A = B * (sk.0 + e).invert().unwrap();

    if A == G1Projective::IDENTITY {
        return Err(Error::SignatureGenerationError("A == Identity_G1".to_owned()));
    }
    
    Ok(BBSplusSignature{ A, e: e})
}


/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-coreverify
/// # Description
/// This operation checks that a signature is valid for a given set of generators, header and vector of messages, against a supplied public key (PK). The set of messages MUST be supplied in this operation in the same order they were supplied to `core_sign` when creating the signature.
///
/// # Inputs:
/// * `pk` (REQUIRED), a public key
/// * `signature` (REQUIRED), a `BBSplusSignature`
/// * `messages` (REQUIRED), a vector of scalars (`BBSplusMessage`) representing the messages, it could be an empty vector.
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application specific information.
/// * `api_id` (OPTIONAL), an octet string. If not supplied it defaults to theempty octet string ("").
/// 
/// # Output:
/// * a result either [`Ok()`] or [`Error`]
pub(super) fn core_verify<CS>(pk: &BBSplusPublicKey, signature: &BBSplusSignature, messages: &[BBSplusMessage], generators: Generators, header: Option<&[u8]>, api_id: Option<&[u8]>) -> Result<(), Error> 
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let L = messages.len();

    if generators.values.len() != L+1 {
        return Err(Error::NotEnoughGenerators);
    }

    let Q1 = generators.values[0];
    let H_points: &[G1Projective] = &generators.values[1..];

    let domain = calculate_domain::<CS>(pk, Q1, H_points, header, api_id)?;

    let mut B = generators.g1_base_point + Q1 * domain;

    for i in 0..L {
        B = B + H_points[i] * messages[i].value;
    }


    let BP2 = G2Projective::GENERATOR;
    let A2 = pk.0 + BP2 * signature.e;

    let identity_GT = Gt::IDENTITY;

    let term1 = (&signature.A.to_affine(), &G2Prepared::from(A2.to_affine()));
    let term2 = (&B.to_affine(), &G2Prepared::from(-BP2.to_affine()));

    let pairing = multi_miller_loop(&[term1, term2]).final_exponentiation();

    if pairing == identity_GT {
        Ok(())
    } else {
        Err(Error::SignatureVerificationError)
    }
}