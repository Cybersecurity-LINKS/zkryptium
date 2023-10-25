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
use crate::{schemes::algorithms::BBSplus, utils::message::BBSplusMessage, bbsplus::{ciphersuites::BbsCiphersuite, generators::{Generators, signer_specific_generators, make_generators}}, utils::util::bbsplus_utils::{calculate_domain, serialize, hash_to_scalar_old}, schemes::generics::Signature};
use elliptic_curve::{hash2curve::ExpandMsg, group::Curve, subtle::{CtOption, Choice}};
use super::keys::{BBSplusPublicKey, BBSplusSecretKey};



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusSignature {
    pub a: G1Projective,
    pub e: Scalar,
    pub s: Scalar,
}

impl BBSplusSignature {
    
    pub fn to_bytes(&self) -> [u8; 112] {
        let mut bytes = [0u8; 112];
        bytes[0..48].copy_from_slice(&self.a.to_affine().to_compressed());
        let e = self.e.to_be_bytes();
        // e.reverse();
        bytes[48..80].copy_from_slice(&e[..]);
        let s = self.s.to_be_bytes();
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
            ee.and_then(|e| ss.and_then(|s| CtOption::new(Self{ a, e, s }, Choice::from(1))))
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

    pub fn s(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.s,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn sign(messages: Option<&[BBSplusMessage]>, sk: &BBSplusSecretKey, pk: &BBSplusPublicKey, generators: Option<&Generators>, header: Option<&[u8]>) -> Self 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let header = header.unwrap_or(b"");

        let messages = messages.unwrap_or(&[]);

        let L = messages.len();

        let generators = match generators {
            Some(gens) => gens.clone(),
            None => {
                let get_generators_fn = make_generators::<CS>;
                let gens = signer_specific_generators(pk, get_generators_fn, L+2);
                gens
            }
            
        };

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

    pub fn verify(&self, pk: &BBSplusPublicKey, messages: Option<&[BBSplusMessage]>, generators: Option<&Generators>, header: Option<&[u8]>) -> bool 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let header = header.unwrap_or(b"");
        let messages = messages.unwrap_or(&[]);
        let signature = self.bbsPlusSignature();

        let L = messages.len();

        let generators = match generators {
            Some(gens) => gens.clone(),
            None => {
                let get_generators_fn = make_generators::<CS>;
                let gens = signer_specific_generators(pk, get_generators_fn, L+2);
                gens
            }
            
        };

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
        self.bbsPlusSignature().to_bytes()
    }

    pub fn from_bytes(data: &[u8; 112]) -> Self {
        Self::BBSplus(BBSplusSignature::from_bytes(data).unwrap())
    }
}