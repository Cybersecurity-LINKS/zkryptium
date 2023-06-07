use std::marker::PhantomData;

use bls12_381_plus::{G1Projective, Scalar, G2Projective, G2Prepared, Gt, multi_miller_loop};
use digest::Digest;
use elliptic_curve::{hash2curve::ExpandMsg, group::Curve};
use num_integer::div_mod_floor;
use rug::{Integer, integer::Order};
use serde::{Serialize, Deserialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, bbsplus::{ciphersuites::BbsCiphersuite, message::{BBSplusMessage, CL03Message}, generators::{self, Generators}}, cl03::ciphersuites::CLCiphersuite, keys::{bbsplus_key::BBSplusPublicKey, cl03_key::{CL03CommitmentPublicKey, CL03PublicKey}}, utils::{util::{get_remaining_indexes, get_messages, calculate_domain, calculate_random_scalars, ScalarExt, hash_to_scalar_old, divm}, random::random_bits}};

use super::{signature::{BBSplusSignature, CL03Signature}, commitment::Commitment};


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusPoKSignature{
    A_prime: G1Projective,
    A_bar: G1Projective,
    D: G1Projective,
    c: Scalar,
    e_cap: Scalar,
    r2_cap: Scalar,
    r3_cap: Scalar,
    s_cap: Scalar,
    m_cap: Vec<Scalar>
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03PoKSignature{
    challenge: Integer,
    s_1: Integer,
    s_2: Integer,
    s_3: Integer,
    s_4: Integer,
    s_5: Vec<Integer>,
    s_6: Integer,
    s_7: Integer,
    s_8: Integer,
    s_9: Integer,
    Cx: Integer,
    Cv: Integer,
    Cw: Integer,
    Ce: Integer,
}

impl CL03PoKSignature {

    pub fn nisp5_MultiAttr_generate_proof<CS: CLCiphersuite>(signature: &CL03Signature, commitment_pk: &CL03CommitmentPublicKey, signer_pk: &CL03PublicKey, messages: &[CL03Message], unrevealed_message_indexes: &[usize]) -> CL03PoKSignature
    where
        CS::HashAlg: Digest
    {
        // let unrevealed_message_indexes: Vec<usize> = match unrevealed_message_indexes {
        //     Some(indexes) => indexes.to_vec(),
        //     None => (0..messages.len()).collect(),
        // };
        let n_attr = messages.len();

        if signer_pk.a_bases.len() != n_attr  && n_attr != commitment_pk.g_bases.len(){
            panic!("Not enough a_bases OR g_bases for the number of attributes");
        }
        
        let C1= Commitment::<CL03<CS>>::commit_with_commitment_pk(messages, commitment_pk, None);
        let (Cx, rx) = (C1.value(), C1.randomness());

        let C2 =  Commitment::<CL03<CS>>::commit_v(&signature.v, commitment_pk);
        let (Cv, w) = (C2.value(), C2.randomness());

        let C3 = Commitment::<CL03<CS>>::commit_with_commitment_pk(&[CL03Message::new(w.clone())], commitment_pk, None);
        let (Cw, rw) = (C3.value(), C3.randomness());

        let C4 = Commitment::<CL03<CS>>::commit_with_commitment_pk(&[CL03Message::new(signature.e.clone())], commitment_pk, None);
        let (Ce, re) = (C4.value(), C4.randomness());

        let (r_1, r_2, r_3, r_4, r_6, r_7, r_8, r_9) = (random_bits(CS::ln), random_bits(CS::ln), random_bits(CS::ln), random_bits(CS::ln), random_bits(CS::ln), random_bits(CS::ln), random_bits(CS::ln), random_bits(CS::ln));
        
        let mut r_5: Vec<Integer> = Vec::new();
        messages.iter().enumerate().for_each(|(i, m)| {
            if unrevealed_message_indexes.contains(&i) {
                r_5.push(random_bits(CS::ln))
            } else {
                r_5.push(m.value.clone());
            }
        });

        let N = &signer_pk.N;

        let mut t_Cx = Integer::from(1);
        for i in 0..n_attr {
            t_Cx = t_Cx * Integer::from(signer_pk.a_bases[i].0.pow_mod_ref(&r_5[i], N).unwrap())
        }

        t_Cx = t_Cx % N;

        let t_1 = (Integer::from(Cv.pow_mod_ref(&r_4, N).unwrap()) * divm(&Integer::from(1), &t_Cx, N) * Integer::from(divm(&Integer::from(1), &signer_pk.b, N).pow_mod_ref(&r_6, N).unwrap()) * Integer::from(divm(&Integer::from(1), &commitment_pk.g_bases[0].0, N).pow_mod_ref(&r_8, N).unwrap())) % N;
        let t_2 = (Integer::from(commitment_pk.g_bases[0].0.pow_mod_ref(&r_7, N).unwrap()) * Integer::from(commitment_pk.h.pow_mod_ref(&r_1, N).unwrap())) % N;
        let t_3 = (Integer::from(Cw.pow_mod_ref(&r_4, N).unwrap()) * Integer::from(divm(&Integer::from(1), &commitment_pk.g_bases[0].0, N).pow_mod_ref(&r_8, N).unwrap()) * Integer::from(divm(&Integer::from(1), &commitment_pk.h, N).pow_mod_ref(&r_2, N).unwrap())) % N;

        let mut t_4 = Integer::from(1);
        for i in 0..n_attr {
            t_4 = t_4 * Integer::from(commitment_pk.g_bases[i].0.pow_mod_ref(&r_5[i], N).unwrap());
        }
        t_4 = (t_4 * Integer::from(commitment_pk.h.pow_mod_ref(&r_3, N).unwrap())) % N;

        let t_5 = (Integer::from(commitment_pk.g_bases[0].0.pow_mod_ref(&r_4, N).unwrap()) * Integer::from(commitment_pk.h.pow_mod_ref(&r_9, N).unwrap())) % N;
        let str =  t_1.to_string() + &t_2.to_string()+ &t_3.to_string()+ &t_4.to_string()+ &t_5.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let s_1 = r_1 + rw * &challenge;
        let s_2 = r_2 + rw * signature.e.clone() * &challenge;
        let s_3 = r_3 + rx * &challenge;
        let s_4 = r_4 + signature.e.clone() * &challenge;
        let mut s_5: Vec<Integer> = Vec::new();
        for i in unrevealed_message_indexes {
            let si = &r_5[*i] + messages[*i].value.clone() * &challenge;
            s_5.push(si);
        }

        let s_6 = r_6 + signature.s.clone() * &challenge;
        let s_7 = r_7 + w * &challenge;   
        let s_8 = r_8 + w * signature.e.clone() * &challenge;
        let s_9 = r_9 + re * &challenge;

        CL03PoKSignature{ challenge, s_1, s_2, s_3, s_4, s_5, s_6, s_7, s_8, s_9, Cx: Cx.clone(), Cv: Cv.clone(), Cw: Cw.clone(), Ce: Ce.clone() }

    }
}


pub enum PoKSignature<S: Scheme>{
    BBSplus(BBSplusPoKSignature),
    CL03(CL03PoKSignature),
    _Unreachable(PhantomData<S>)
}


impl <CS: BbsCiphersuite> PoKSignature<BBSplus<CS>> {

    fn calculate_challenge(A_prime: G1Projective, Abar: G1Projective, D: G1Projective, C1: G1Projective, C2: G1Projective, i_array: &[usize], msg_array: &[BBSplusMessage], domain: Scalar, ph: Option<&[u8]>) -> Scalar
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let ph = ph.unwrap_or(b"");
        
        let R = i_array.len();
        if R != msg_array.len() {
            panic!("R != msg_array.len()");
        }

        let mut c_array: Vec<u8> = Vec::new();
        c_array.extend_from_slice(&A_prime.to_affine().to_compressed());
        c_array.extend_from_slice(&Abar.to_affine().to_compressed());
        c_array.extend_from_slice(&D.to_affine().to_compressed());
        c_array.extend_from_slice(&C1.to_affine().to_compressed());
        c_array.extend_from_slice(&C2.to_affine().to_compressed());
        c_array.extend_from_slice(&R.to_be_bytes());
        i_array.iter().for_each(|i| c_array.extend(i.to_be_bytes().iter()));
        msg_array.iter().for_each(|m| c_array.extend_from_slice(&m.value.to_bytes_be()));
        c_array.extend_from_slice(&domain.to_bytes_be());

        let ph_i2osp: [u8; 8] = (ph.len() as u64).to_be_bytes();
        c_array.extend_from_slice(&ph_i2osp);
        c_array.extend_from_slice(ph);

        let challenge = hash_to_scalar_old::<CS>(&c_array, 1, None);

        challenge[0]
    }

    pub fn proof_gen(signature: &BBSplusSignature, pk: &BBSplusPublicKey, messages: Option<&[BBSplusMessage]>, generators: &Generators, revealed_message_indexes: Option<&[usize]>, header: Option<&[u8]>, ph: Option<&[u8]>, seed: Option<&[u8]>) -> Self
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let messages = messages.unwrap_or(&[]);
        let revealed_message_indexes = revealed_message_indexes.unwrap_or(&[]);
        let header = header.unwrap_or(b"");
        let ph = ph.unwrap_or(b"");
        let seed = seed.unwrap_or(b"");

        let L = messages.len();
        let R = revealed_message_indexes.len();
        let U = L - R;

        let unrevealed_message_indexes = get_remaining_indexes(L, revealed_message_indexes);

        let revealed_messages = get_messages(messages, revealed_message_indexes);
        let unrevealed_messages = get_messages(messages, &unrevealed_message_indexes);

        if generators.message_generators.len() < L {
            panic!("not enough message generators!");
        }

        let mut H_j: Vec<G1Projective> = Vec::new();

        for idx in unrevealed_message_indexes {
            H_j.push(generators.message_generators[idx]);
        }

        let domain = calculate_domain::<CS>(pk, generators.q1, generators.q2, &generators.message_generators, Some(header));

        let random_scalars = calculate_random_scalars::<CS>(6+U, Some(seed));

        let r1 = random_scalars[0];
        let r2 = random_scalars[1];
        let e_tilde = random_scalars[2];
        let r2_tilde = random_scalars[3];
        let r3_tilde = random_scalars[4];
        let s_tilde = random_scalars[5];

        let m_tilde = &random_scalars[6..(6+U)];

        let mut B = generators.g1_base_point + generators.q1 * signature.s + generators.q2 * domain;

        for i in 0..L {
            B = B + generators.message_generators[i] * messages[i].value;
        }

        let r3 = r1.invert().unwrap();

        let A_prime = signature.a * r1;

        let A_bar = A_prime * (-signature.e) + B * r1;

        let D = B * r1 + generators.q1 * r2;

        let s_prime = r2 * r3 + signature.s;

        let C1 = A_prime * e_tilde + generators.q1 * r2_tilde;

        let mut C2 = D * (-r3_tilde) + generators.q1 * s_tilde;

        for idx in 0..U{
            C2 = C2 + H_j[idx] * m_tilde[idx];
        }

        let c = Self::calculate_challenge(A_prime, A_bar, D, C1, C2, revealed_message_indexes, &revealed_messages, domain, Some(ph));

        let e_cap = c * signature.e + e_tilde;

        let r2_cap = c * r2 + r2_tilde;

        let r3_cap = c * r3 + r3_tilde;

        let s_cap = c * s_prime + s_tilde;

        let mut m_cap: Vec<Scalar> = Vec::new();

        for idx in 0..U {
            let value = c * unrevealed_messages[idx].value + m_tilde[idx];
            m_cap.push(value);
        }

        let proof = Self::BBSplus(BBSplusPoKSignature{ A_prime, A_bar, D, c, e_cap, r2_cap, r3_cap, s_cap, m_cap });

        proof
    }

    pub fn proof_verify(&self, pk: &BBSplusPublicKey, revealed_messages: Option<&[BBSplusMessage]>, generators: &Generators, revealed_message_indexes: Option<&[usize]>, header: Option<&[u8]>, ph: Option<&[u8]>) -> bool 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let proof = self.to_bbsplus_proof();
        let revealed_messages = revealed_messages.unwrap_or(&[]);
        let revealed_message_indexes = revealed_message_indexes.unwrap_or(&[]);
        let header = header.unwrap_or(b"");
        let ph = ph.unwrap_or(b"");

        let U = proof.m_cap.len();
        let R = revealed_message_indexes.len();

        let L = R + U;

        let unrevealed_message_indexes = get_remaining_indexes(L, revealed_message_indexes);

        for i in revealed_message_indexes {
            if *i < 0 || *i > L {
                panic!("i < 0 or i >= L");
            }
        }

        if revealed_messages.len() != R {
            panic!("len(revealed_messages) != R");
        }

        if generators.message_generators.len() < L {
            panic!("len(generators) < (L)");
        }

        let mut H_i: Vec<G1Projective> = Vec::new();

        for idx in revealed_message_indexes {
            H_i.push(generators.message_generators[*idx]);
        }

        let mut H_j: Vec<G1Projective> = Vec::new();

        for idx in unrevealed_message_indexes {
            H_j.push(generators.message_generators[idx]);
        }

        let domain = calculate_domain::<CS>(pk, generators.q1, generators.q2, &generators.message_generators, Some(header));

        let C1 = (proof.A_bar + (-proof.D)) * proof.c + proof.A_prime * proof.e_cap + generators.q1 * proof.r2_cap;
		
		let mut T = generators.g1_base_point + generators.q2 * domain;		
		for i in 0..R { 
			T = T + H_i[i] * revealed_messages[i].value;
        }		

		let mut C2 = T * proof.c + proof.D * -proof.r3_cap + generators.q1 * proof.s_cap;
		for j in 0..U {
            C2 = C2 + H_j[j] * proof.m_cap[j];
        }

		let cv = Self::calculate_challenge(proof.A_prime, proof.A_bar, proof.D, C1, C2, revealed_message_indexes, revealed_messages, domain, Some(ph));
        
        if proof.c != cv {
			return false;
        }

		if proof.A_prime == G1Projective::IDENTITY{
			return false;
        }


        let P2 = G2Projective::GENERATOR;
        let identity_GT = Gt::IDENTITY;

        let Ps = (&proof.A_prime.to_affine(), &G2Prepared::from(pk.0.to_affine()));
		let Qs = (&proof.A_bar.to_affine(), &G2Prepared::from(-P2.to_affine()));

        let pairing = multi_miller_loop(&[Ps, Qs]).final_exponentiation();

        pairing == identity_GT

    }

        // A_prime: G1Projective, //48
        // A_bar: G1Projective, //48
        // D: G1Projective, //48
        // c: Scalar, //32
        // e_cap: Scalar, //32
        // r2_cap: Scalar, //32
        // r3_cap: Scalar, //32
        // s_cap: Scalar, //32
        // m_cap: Vec<Scalar> //32 * len(m_cap)
    pub fn to_bytes(&self) -> Vec<u8>{
        let signature = self.to_bbsplus_proof();
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&signature.A_prime.to_affine().to_compressed());
        bytes.extend_from_slice(&signature.A_bar.to_affine().to_compressed());
        bytes.extend_from_slice(&signature.D.to_affine().to_compressed());
        bytes.extend_from_slice(&signature.c.to_bytes_be());
        bytes.extend_from_slice(&signature.e_cap.to_bytes_be());
        bytes.extend_from_slice(&signature.r2_cap.to_bytes_be());
        bytes.extend_from_slice(&signature.r3_cap.to_bytes_be());
        bytes.extend_from_slice(&signature.s_cap.to_bytes_be());
        signature.m_cap.iter().for_each(|v| bytes.extend_from_slice(&v.to_bytes_be()));
        
        bytes
    }

    pub fn to_bbsplus_proof(&self) ->  &BBSplusPoKSignature {
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }
}

impl <CS: CLCiphersuite> PoKSignature<CL03<CS>> {

}