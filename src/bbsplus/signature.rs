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



use bls12_381_plus::{G1Projective, Scalar, G1Affine, G2Projective, Gt, multi_miller_loop, G2Prepared};
use ff::Field;
use serde::{Deserialize, Serialize};
use crate::{bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, errors::Error, schemes::{algorithms::BBSplus, generics::Signature}, utils::{message::BBSplusMessage, util::bbsplus_utils::{calculate_domain, calculate_domain_new, hash_to_scalar_new, hash_to_scalar_old, serialize}}};
use elliptic_curve::{hash2curve::ExpandMsg, group::Curve, subtle::{CtOption, Choice}};
use super::{generators, keys::{BBSplusPublicKey, BBSplusSecretKey}};



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusSignature {
    pub a: G1Projective,
    pub e: Scalar,
    // pub s: Scalar,
}

impl BBSplusSignature {

    pub const SIGNATURE_LENGHT: usize = 80;
    
    pub fn to_bytes(&self) -> [u8; Self::SIGNATURE_LENGHT] {
        let mut bytes = [0u8; Self::SIGNATURE_LENGHT];
        bytes[0..48].copy_from_slice(&self.a.to_affine().to_compressed());
        let e = self.e.to_be_bytes();
        bytes[48..80].copy_from_slice(&e[..]);
        bytes
    }

    pub fn from_bytes(data: &[u8; Self::SIGNATURE_LENGHT]) -> CtOption<Self> {
        let aa = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[0..48]).unwrap())
            .map(G1Projective::from);
        let e_bytes = <[u8; 32]>::try_from(&data[48..80]).unwrap();
        let ee = Scalar::from_be_bytes(&e_bytes);
        // let s_bytes = <[u8; 32]>::try_from(&data[80..112]).unwrap();
        // let ss = Scalar::from_be_bytes(&s_bytes);

        aa.and_then(|a| {
            ee.and_then(|e| CtOption::new(Self{ a, e }, Choice::from(1)))
        })
    }
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

    pub fn to_bytes(&self) -> [u8; BBSplusSignature::SIGNATURE_LENGHT] {
        self.bbsPlusSignature().to_bytes()
    }

    pub fn from_bytes(data: &[u8; BBSplusSignature::SIGNATURE_LENGHT]) -> Self {
        Self::BBSplus(BBSplusSignature::from_bytes(data).unwrap())
    }



    pub fn update_signature(&self, sk: &BBSplusSecretKey, generators: &Generators, old_message: &BBSplusMessage, new_message: &BBSplusMessage, update_index: usize) -> Self {

        if generators.values.len()+1 <= update_index {
            panic!("len(generators) <= update_index");
        }
        let H_points = &generators.values[1..];
        let H_i = H_points.get(update_index).expect("index overflow");
        let SK_plus_e = sk.0 + self.e();
        let mut B = self.a() * SK_plus_e;
        B = B + (-H_i * old_message.value);
        B = B + (H_i * new_message.value);
        let A = B * SK_plus_e.invert().unwrap();

        if A == G1Projective::IDENTITY{
            panic!("A == IDENTITY G1");
        }

        return Self::BBSplus(BBSplusSignature { a: A, e: self.e() })
    }
}


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

    let domain = calculate_domain_new::<CS>(pk, Q1, H_points, header, Some(api_id))?;

    //serialize 
    let mut input: Vec<Scalar> = Vec::new();
    input.push(sk.0);
    input.push(domain);
    messages.iter().for_each(|m| input.push(m.value)); //the to_byte_le() may be needed instead

    let e = hash_to_scalar_new::<CS>(&serialize(&input), &signature_dst)?;

    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L

    let mut B = generators.g1_base_point + Q1 * domain;

    for i in 0..L {
        B = B + H_points[i] * messages[i].value;
    }

    // A = B * (1 / (SK + e))
    let A = B * (sk.0 + e).invert().unwrap();

    if A == G1Projective::IDENTITY {
        panic!("A == Identity_G1");
    }

    
    Ok(BBSplusSignature{ a: A, e: e})
}


fn core_verify<CS>(pk: &BBSplusPublicKey, signature: &BBSplusSignature, messages: &[BBSplusMessage], generators: Generators, header: Option<&[u8]>, api_id: Option<&[u8]>) -> Result<(), Error> 
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

    let domain = calculate_domain_new::<CS>(pk, Q1, H_points, header, api_id)?;

    let mut B = generators.g1_base_point + Q1 * domain;

    for i in 0..L {
        B = B + H_points[i] * messages[i].value;
    }


    let BP2 = G2Projective::GENERATOR;
    let A2 = pk.0 + BP2 * signature.e;

    let identity_GT = Gt::IDENTITY;

    let term1 = (&signature.a.to_affine(), &G2Prepared::from(A2.to_affine()));
    let term2 = (&B.to_affine(), &G2Prepared::from(-BP2.to_affine()));

    let pairing = multi_miller_loop(&[term1, term2]).final_exponentiation();

    if pairing == identity_GT {
        Ok(())
    } else {
        Err(Error::SignatureVerificationError)
    }
}