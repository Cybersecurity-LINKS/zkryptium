use std::{marker::PhantomData};

use bls12_381_plus::{G1Projective, Scalar, G2Projective, G2Prepared, Gt, multi_miller_loop};
use digest::Digest;
use elliptic_curve::{hash2curve::ExpandMsg, group::Curve};
use rug::{Integer, integer::Order, ops::{Pow}, Complete};
use serde::{Serialize, Deserialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, bbsplus::{ciphersuites::BbsCiphersuite, message::{BBSplusMessage, CL03Message}, generators::{Generators}}, cl03::ciphersuites::{CLCiphersuite}, keys::{bbsplus_key::BBSplusPublicKey, cl03_key::{CL03CommitmentPublicKey, CL03PublicKey}}, utils::{util::{get_remaining_indexes, get_messages, calculate_domain, calculate_random_scalars, ScalarExt, hash_to_scalar_old, divm}, random::{random_bits, rand_int}}};

use super::{signature::{BBSplusSignature, CL03Signature}, commitment::{Commitment, CL03Commitment, BBSplusCommitment}};

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
struct ProofOfValue {
    value: NISPSecrets,
    commitment: CL03Commitment 
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03PoKSignature {
    spok: NISPSignaturePoK,
    range_proof_e: Boudot2000RangeProof,
    proofs_commited_mi: Vec<ProofOfValue>,
    range_proofs_commited_mi: Vec<Boudot2000RangeProof>
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
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
            H_j.push(*generators.message_generators.get(idx).expect("unrevealed_message_indexes not valid (overflow)"));
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
            B = B + generators.message_generators.get(i).expect("index overflow") * messages.get(i).expect("index overflow").value;
        }

        let r3 = r1.invert().unwrap();

        let A_prime = signature.a * r1;

        let A_bar = A_prime * (-signature.e) + B * r1;

        let D = B * r1 + generators.q1 * r2;

        let s_prime = r2 * r3 + signature.s;

        let C1 = A_prime * e_tilde + generators.q1 * r2_tilde;

        let mut C2 = D * (-r3_tilde) + generators.q1 * s_tilde;

        for idx in 0..U{
            C2 = C2 + H_j.get(idx).expect("index overflow") * m_tilde.get(idx).expect("index overflow");
        }

        let c = Self::calculate_challenge(A_prime, A_bar, D, C1, C2, revealed_message_indexes, &revealed_messages, domain, Some(ph));

        let e_cap = c * signature.e + e_tilde;

        let r2_cap = c * r2 + r2_tilde;

        let r3_cap = c * r3 + r3_tilde;

        let s_cap = c * s_prime + s_tilde;

        let mut m_cap: Vec<Scalar> = Vec::new();

        for idx in 0..U {
            let value = c * unrevealed_messages.get(idx).expect("index overflow").value + m_tilde.get(idx).expect("index overflow");
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

    pub fn proof_gen(signature: &CL03Signature, commitment_pk: &CL03CommitmentPublicKey, signer_pk: &CL03PublicKey, messages: &[CL03Message], unrevealed_message_indexes: &[usize]) -> Self 
    where
        CS::HashAlg: Digest
    {

        let min_e = Integer::from(2).pow(CS::le - 1) + 1;
        let max_e = Integer::from(2).pow(CS::le) - 1;
        let min_x = Integer::from(0);  
        let max_x = Integer::from(2).pow(CS::lm) - 1;

        let spok = NISPSignaturePoK::nisp5_MultiAttr_generate_proof::<CS>(signature, commitment_pk, signer_pk, messages, unrevealed_message_indexes);

        //range proof e
        let r_proof_e = match CS::RANGEPROOF_ALG {
            RangeProof::Boudot2000 => Boudot2000RangeProof::prove::<CS::HashAlg>(&signature.e, &spok.Ce, &commitment_pk.g_bases[0].0, &commitment_pk.h, &commitment_pk.N, &min_e, &max_e),
        };

        let mut proofs_mi: Vec<ProofOfValue> = Vec::new();
        let mut r_proofs_mi: Vec<Boudot2000RangeProof> = Vec::new();
        for i in unrevealed_message_indexes {
            let mi = messages.get(*i).expect("unreaveled_message_indexes not valid with respect to the messages!");
            let gi = &commitment_pk.g_bases.get(*i).expect("unreaveled_message_indexes not valid with respect to the commitment_pk.g_bases!").0;
            let cmi = Commitment::<CL03<CS>>::commit_with_commitment_pk(&[mi.clone()], commitment_pk, None).cl03Commitment().to_owned();
            let proof_mi_ri = NISPSecrets::nisp2sec_generate_proof::<CS>(mi, &cmi, &gi, &commitment_pk.h, &commitment_pk.N);
            proofs_mi.push(ProofOfValue { value: proof_mi_ri, commitment: cmi.clone()});
            let r_proof_mi = match CS::RANGEPROOF_ALG {
                RangeProof::Boudot2000 => Boudot2000RangeProof::prove::<CS::HashAlg>(&mi.value, &cmi, &gi, &commitment_pk.h, &commitment_pk.N, &min_x, &max_x),
            };

            r_proofs_mi.push(r_proof_mi);
        }

        
        Self::CL03(CL03PoKSignature{spok, range_proof_e: r_proof_e, proofs_commited_mi: proofs_mi, range_proofs_commited_mi: r_proofs_mi})

    }

    pub fn proof_verify(&self, commitment_pk: &CL03CommitmentPublicKey, signer_pk: &CL03PublicKey, messages: &[CL03Message], unrevealed_message_indexes: &[usize], n_signed_messages: usize) ->bool
    where
        CS::HashAlg: Digest
    {

        let min_e = Integer::from(2).pow(CS::le - 1) + 1;
        let max_e = Integer::from(2).pow(CS::le) - 1;
        let min_x = Integer::from(0);  
        let max_x = Integer::from(2).pow(CS::lm) - 1;
        let CLSPoK = self.to_cl03_proof();
        let boolean_spok = NISPSignaturePoK::nisp5_MultiAttr_verify_proof::<CS>(&CLSPoK.spok, commitment_pk, signer_pk, messages, unrevealed_message_indexes, n_signed_messages);
        if !boolean_spok {
            println!("Signature PoK Failed!");
            return false;
        }
        if CLSPoK.spok.Ce.value == CLSPoK.range_proof_e.E {
            //Verify RANGE PROOFS e
            let boolean_rproof_e = CLSPoK.range_proof_e.verify::<CS::HashAlg>(&commitment_pk.g_bases[0].0, &commitment_pk.h, &commitment_pk.N, &min_e, &max_e);
            
            if boolean_rproof_e {
                //Verify RANGE PROOFS mi
                let mut idx: usize = 0;
                for i in unrevealed_message_indexes {
                    
                    let gi = &commitment_pk.g_bases.get(*i).expect("unreaveled_message_indexes not valid with respect to the commitment_pk.g_bases!").0;
                    let ProofOfValue{value: proof_mi, commitment: cmi} = CLSPoK.proofs_commited_mi.get(idx).expect("index overflow");
                    let boolean_proof_mi = proof_mi.nisp2sec_verify_proof::<CS>(&cmi, gi, &commitment_pk.h, &commitment_pk.N);
                    if !boolean_proof_mi {
                        println!("Knowledge verification of mi Failed!");
                        return false;
                    }
                    let boolean_rproofs_mi = CLSPoK.range_proofs_commited_mi.get(idx).expect("index overflow").verify::<CS::HashAlg>(&gi, &commitment_pk.h, &commitment_pk.N, &min_x, &min_x);
                    if !boolean_rproofs_mi {
                        println!("Range proof verification on mi Failed!");
                        return false;
                    }

                }
            }
            else {
                println!("Range proof verification on e Failed!");
                return false;
            }
        }
        else {
            println!("Commitment on 'e' used in the SPoK different from the one used in the Range Proof!");
            return false
        }

        true
    }


    pub fn to_cl03_proof(&self) ->  &CL03PoKSignature {
        match self {
            Self::CL03(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct NISPSignaturePoK{
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
    Cx: CL03Commitment,
    Cv: CL03Commitment,
    Cw: CL03Commitment,
    Ce: CL03Commitment,
}

impl NISPSignaturePoK {

    pub fn nisp5_MultiAttr_generate_proof<CS: CLCiphersuite>(signature: &CL03Signature, commitment_pk: &CL03CommitmentPublicKey, signer_pk: &CL03PublicKey, messages: &[CL03Message], unrevealed_message_indexes: &[usize]) -> NISPSignaturePoK
    where
        CS::HashAlg: Digest
    {
        // let unrevealed_message_indexes: Vec<usize> = match unrevealed_message_indexes {
        //     Some(indexes) => indexes.to_vec(),
        //     None => (0..messages.len()).collect(),
        // };
        let n_attr = messages.len();

        if signer_pk.a_bases.len() < n_attr  && n_attr < commitment_pk.g_bases.len(){
            panic!("Not enough a_bases OR g_bases for the number of attributes");
        }
        
        let C_Cx= Commitment::<CL03<CS>>::commit_with_commitment_pk(messages, commitment_pk, None);
        let (Cx, rx) = (C_Cx.value(), C_Cx.randomness());

        let C_Cv =  Commitment::<CL03<CS>>::commit_v(&signature.v, commitment_pk);
        let (Cv, w) = (C_Cv.value(), C_Cv.randomness());

        let C_Cw = Commitment::<CL03<CS>>::commit_with_commitment_pk(&[CL03Message::new(w.clone())], commitment_pk, None);
        let (Cw, rw) = (C_Cw.value(), C_Cw.randomness());

        let C_Ce = Commitment::<CL03<CS>>::commit_with_commitment_pk(&[CL03Message::new(signature.e.clone())], commitment_pk, None);
        let (Ce, re) = (C_Ce.value(), C_Ce.randomness());

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
            let si = r_5.get(*i).expect("unrevealed_message_indexes not valid (overflow)") + messages.get(*i).expect("unrevealed_message_indexes not valid (overflow)").value.clone() * &challenge;
            s_5.push(si);
        }

        let s_6 = r_6 + signature.s.clone() * &challenge;
        let s_7 = r_7 + w * &challenge;   
        let s_8 = r_8 + w * signature.e.clone() * &challenge;
        let s_9 = r_9 + re * &challenge;

        NISPSignaturePoK{ challenge, s_1, s_2, s_3, s_4, s_5, s_6, s_7, s_8, s_9, Cx: C_Cx.cl03Commitment().clone(), Cv: C_Cv.cl03Commitment().clone(), Cw: C_Cw.cl03Commitment().clone(), Ce: C_Ce.cl03Commitment().clone() }

    }

    pub fn nisp5_MultiAttr_verify_proof<CS: CLCiphersuite>(&self, commitment_pk: &CL03CommitmentPublicKey, signer_pk: &CL03PublicKey, messages: &[CL03Message], unrevealed_message_indexes: &[usize], n_signed_messages: usize) -> bool
    where
        CS::HashAlg: Digest
    {

        if signer_pk.a_bases.len() < n_signed_messages  && n_signed_messages < commitment_pk.g_bases.len(){
            panic!("Not enough a_bases OR g_bases for the number of attributes");
        }

        let mut t_Cx = Integer::from(1);
        let N = &signer_pk.N;
        let mut idx: usize = 0;
        let mut idx_revealed_msgs: usize = 0;
        
        for i in 0..n_signed_messages {
            if unrevealed_message_indexes.contains(&i) {
                t_Cx = &t_Cx * Integer::from(signer_pk.a_bases[i].0.pow_mod_ref(&self.s_5[idx], N).unwrap());
                idx += 1;
            } else {
                let val = (&messages.get(idx_revealed_msgs).expect("index overflow!").value + &messages[idx].value).complete() * &self.challenge;
                t_Cx = &t_Cx * Integer::from(signer_pk.a_bases[i].0.pow_mod_ref(&val, N).unwrap());
                idx_revealed_msgs += 1;
            }
        }
        t_Cx = t_Cx % N;

        let input1 = (Integer::from(self.Cv.value.pow_mod_ref(&self.s_4, N).unwrap()) * divm(&Integer::from(1), &t_Cx, N) * Integer::from(divm(&Integer::from(1), &signer_pk.b, N).pow_mod_ref(&self.s_6, N).unwrap()) * Integer::from(divm(&Integer::from(1), &commitment_pk.g_bases[0].0, N).pow_mod_ref(&self.s_8, N).unwrap()) * Integer::from(signer_pk.c.pow_mod_ref(&(Integer::from(-1) * &self.challenge), N).unwrap())) % N;
        let input2 = (Integer::from(commitment_pk.g_bases[0].0.pow_mod_ref(&self.s_7, N).unwrap()) * Integer::from(commitment_pk.h.pow_mod_ref(&self.s_1, N).unwrap()) * Integer::from(self.Cw.value.pow_mod_ref(&(Integer::from(-1) * &self.challenge), N).unwrap()) ) % N;
        let input3 = (Integer::from(self.Cw.value.pow_mod_ref(&self.s_4, N).unwrap()) * Integer::from(divm(&Integer::from(1), &commitment_pk.g_bases[0].0, N).pow_mod_ref(&self.s_8, N).unwrap()) * Integer::from(divm(&Integer::from(1), &commitment_pk.h, N).pow_mod_ref(&self.s_2, N).unwrap())) % N;

        let mut input4 = Integer::from(1);
        let mut idx: usize = 0;
        let mut idx_revealed_msgs: usize = 0;

        for i in 0..n_signed_messages {
            if unrevealed_message_indexes.contains(&i) {
                input4 = &input4 * Integer::from(commitment_pk.g_bases[i].0.pow_mod_ref(&self.s_5[idx], N).unwrap());
                idx += 1;
            } else {
                let val = (&messages.get(idx_revealed_msgs).expect("index overflow").value + &messages[idx_revealed_msgs].value).complete() * &self.challenge;
                t_Cx = &t_Cx * Integer::from(commitment_pk.g_bases[i].0.pow_mod_ref(&val, N).unwrap());
                idx_revealed_msgs += 1;
            }
        }

        input4 = (input4 * Integer::from(commitment_pk.h.pow_mod_ref(&self.s_3, N).unwrap()) * Integer::from(self.Cx.value.pow_mod_ref(&(Integer::from(-1) * &self.challenge), N).unwrap())) % N;

        let input5 = (Integer::from(commitment_pk.g_bases[0].0.pow_mod_ref(&self.s_4, N).unwrap()) * Integer::from(commitment_pk.h.pow_mod_ref(&self.s_9, N).unwrap()) * Integer::from(self.Ce.value.pow_mod_ref(&(Integer::from(-1) * &self.challenge), N).unwrap()) ) % N;
        
        let str =  input1.to_string() + &input2.to_string()+ &input3.to_string()+ &input4.to_string()+ &input5.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        challenge == self.challenge
    }
}


//RANGE PROOF

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct ProofSs {
    challenge: Integer,
    d: Integer,
    d_1: Integer,
    d_2: Integer
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct ProofOfS {
    E: Integer,
    F: Integer,
    proof_ss: ProofSs
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct ProofLi {
    C: Integer,
    D_1: Integer,
    D_2: Integer
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct ProofWt {
    E_a_1: Integer,
    E_a_2: Integer,
    E_b_1: Integer,
    E_b_2: Integer,
    proof_of_square_a: ProofOfS,
    proof_of_square_b: ProofOfS,
    proof_large_i_a: ProofLi,
    proof_large_i_b: ProofLi
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Boudot2000RangeProof {
    proof_of_tolerance: ProofWt,
    E_prime: Integer,
    E: Integer,
}


impl Boudot2000RangeProof {

    /* Security parameter - Half of the length of the Hash function output
    NOTE: i.e., 2*t bits is the length of the Hash function output. 
    The soundness characteristic of the range proof is given by 2**(t−1).                    
    t = 80: Original value in [Boudot2000], appropriate for SHA-1 - sha160 (i.e. 2*t = 160 bits),
    replaced by t = 128, appropriate for SHA256 (i.e. 2*t = 256). */
    const t: u32 = 128;
    // Security parameter - Zero knowledge property is guaranteed given that 1∕l is negligible
    const l: u32 = 40;
    // Security parameter for the commitment - 2**s  must be negligible
    const s: u32 = 40;
    // Security parameter for the commitment - 2**s1 must be negligible
    const s1: u32 = 40;
    // Security parameter for the commitment - 2**s2 must be negligible
    const s2: u32 = 552;


    /* Algorithm 1 Proof of Same Secret */ 
    fn proof_same_secret<H>(x: &Integer, r_1: &Integer, r_2: &Integer, g_1: &Integer, h_1: &Integer, g_2: &Integer, h_2: &Integer, l: u32, t: u32, b: &Integer, s1: u32, s2: u32, n: &Integer) -> ProofSs
    where
        H: Digest
    {

        let omega = rand_int(Integer::from(1), Integer::from(2).pow(l + t) * b - Integer::from(1));
        let mu_1 = rand_int(Integer::from(1), Integer::from(2).pow(l + t + s1) * n - Integer::from(1));
        let mu_2 = rand_int(Integer::from(1), Integer::from(2).pow(l + t + s2) * n - Integer::from(1));
        let w_1 = (Integer::from(g_1.pow_mod_ref(&omega, n).unwrap()) * Integer::from(h_1.pow_mod_ref(&mu_1, n).unwrap()) ) % n;
        let w_2 = (Integer::from(g_2.pow_mod_ref(&omega, n).unwrap()) * Integer::from(h_2.pow_mod_ref(&mu_2, n).unwrap()) ) % n;

        let str =  w_1.to_string() + &w_2.to_string();
        let hash = <H as Digest>::digest(str);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let d = omega + &challenge * x;
        let d_1 = mu_1 + &challenge * r_1;
        let d_2 = mu_2 + &challenge * r_2;


        ProofSs{challenge, d, d_1, d_2}
        // proof_ss = {'challenge': int(challenge), 'd': int(d), 'd_1': int(d_1), 'd_2': int(d_2)}
    }

    /* Algorithm 2 Verify Proof of Same Secret*/
    fn verify_same_secret<H>(E: &Integer, F: &Integer, g_1: &Integer, h_1: &Integer, g_2: &Integer, h_2: &Integer, n: &Integer, proof_ss: &ProofSs) -> bool
    where
        H: Digest
    {

        let ProofSs{challenge, d, d_1, d_2} = proof_ss;
        
        let inv_E = Integer::from(E.pow_mod_ref(&(-Integer::from(1) * challenge), n).unwrap());
        let inv_F = Integer::from(F.pow_mod_ref(&(-Integer::from(1) * challenge), n).unwrap());

        let lhs = (Integer::from(g_1.pow_mod_ref(d, n).unwrap()) * Integer::from(h_1.pow_mod_ref(d_1, n).unwrap()) * &inv_E) % n;
        let rhs = (Integer::from(g_2.pow_mod_ref(d, n).unwrap()) * Integer::from(h_2.pow_mod_ref(d_2, n).unwrap()) * &inv_F) % n;

        let str =  lhs.to_string() + &rhs.to_string();
        let hash = <H as Digest>::digest(str);
        let output = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        challenge == &output

    }

    /* Algorithm 3 Proof of Square */
    fn proof_of_square<H>(x: &Integer, r_1: &Integer, g: &Integer, h: &Integer, E: &Integer, l: u32, t: u32, b: &Integer, s: u32, s1: u32, s2: u32, n: &Integer) -> ProofOfS
    where
        H: Digest
    {

        let r_2 = rand_int(-Integer::from(2).pow(s) * n + Integer::from(1), Integer::from(2).pow(s) * n - Integer::from(1));
        let F = (Integer::from(g.pow_mod_ref(x, n).unwrap()) * Integer::from(h.pow_mod_ref(&r_2, n).unwrap())) % n;
        let r_3 = r_1 - (&r_2 * x).complete();

        let proof_ss = Self::proof_same_secret::<H>(x, &r_2, &r_3, g, h, &F, h, l, t, b, s1, s2, n);
        // proof_of_s = {'E': int(E), 'F': int(F), 'proof_ss': proof_ss}
        ProofOfS{E: E.clone(), F, proof_ss}
    }

    /* Algorithm 4 Verify Proof of Square */
    fn verify_of_square<H>(proof_of_s: &ProofOfS, g: &Integer, h: &Integer, n: &Integer) -> bool
    where
        H: Digest
    {
        Self::verify_same_secret::<H>(&proof_of_s.F, &proof_of_s.E, g, h, &proof_of_s.F, h, n, &proof_of_s.proof_ss)
    }

    /* Algorithm 5 Proof of Larger Interval Specific factor 2 ** T */
    fn proof_large_interval_specific<H>(x: &Integer, r: &Integer, g: &Integer, h: &Integer, t: u32, l: u32, b: &Integer, s: u32, n: &Integer, T: u32) -> ProofLi
    where
        H: Digest
    {

        let mut boolean = true;
        let mut C = Integer::from(0);
        let mut D_1 = Integer::from(0);
        let mut D_2= Integer::from(0);

        while boolean {
            let w = rand_int(Integer::from(0), (Integer::from(2).pow(T) * Integer::from(2).pow(t + l)) * b - Integer::from(1));
            let nu = rand_int(-(Integer::from(2).pow(T) * Integer::from(2).pow(t + l + s)) * n + Integer::from(1), (Integer::from(2).pow(T) * Integer::from(2).pow(t + l + s)) * n - Integer::from(1));
            let omega = (Integer::from(g.pow_mod_ref(&w, n).unwrap()) * Integer::from(h.pow_mod_ref(&nu, n).unwrap())) % n;

            let str =  omega.to_string();
            let hash = <H as Digest>::digest(str);
            C = Integer::from_digits(hash.as_slice(), Order::MsfBe);

            let c = &C % (Integer::from(2).pow(t));

            D_1 = w + (x * &c);
            D_2 = nu + (r * &c);

            if c * b <= D_1 && D_1 <= (Integer::from(2).pow(T) * Integer::from(2).pow(t + l)) * b - Integer::from(1) {
                boolean = false;
            }

        }

        // proof_li = {'C': int(C), 'D_1': int(D_1), 'D_2': int(D_2)}
        ProofLi{C, D_1, D_2}
    }

    /* Algorithm 6 Verify Proof of Larger Interval Specific factor 2 ** T */
    fn verify_large_interval_specific<H>(proof_li: &ProofLi, E: &Integer, g: &Integer, h: &Integer, n: &Integer, t: u32, l: u32, b: &Integer, T: u32) -> bool
    where
        H: Digest
    {

        let ProofLi {C, D_1, D_2} = proof_li;
        let c = C % (Integer::from(2).pow(t));
        let inv_E = Integer::from(E.pow_mod_ref(&(-Integer::from(1) * &c), n).unwrap());
        let commit = (Integer::from(g.pow_mod_ref(D_1, n).unwrap()) * Integer::from(h.pow_mod_ref(D_2, n).unwrap()) * &inv_E) % n;

        let str =  commit.to_string();
        let hash = <H as Digest>::digest(str);
        let output = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        if &(c * Integer::from(b)) <= D_1 && D_1 <= &(Integer::from(2).pow(T) * (Integer::from(2).pow(t+l) * b - Integer::from(1))) && C == &output {
            return true
        }

        false
    }

    /* Algorithm 7 Proof with Tolerance Specific factor 2 ** T */
    fn proof_of_tolerance_specific<H>(x: Integer, r: Integer, g: &Integer, h: &Integer, n: &Integer, a: &Integer, b: &Integer, t: u32, l: u32, s: u32, s1: u32, s2: u32, T: u32) -> ProofWt
    where
        H: Digest
    {
        /* # NOTE: the first step of this algorithm (see Section 3.1.1 in [Boudot2000])
        #       requires a proof of knowledge of x and r related to the Commitment E = g**x * h**r % n
        #       (i.e., NON-Interactive Sigma protocol of Two secrets - nisp2sec).           
        #       We SKIP such Sigma protocol, assuming that this PoK was already done before the range proof. */

        let aa = Integer::from(2).pow(T) * Integer::from(a) - Integer::from(2).pow(l + t + rug::ops::DivRounding::div_floor(T, 2) + 1) * Integer::from(Integer::from(b - a).sqrt_ref());

        let bb = Integer::from(2).pow(T) * Integer::from(b) + Integer::from(2).pow(l + t + rug::ops::DivRounding::div_floor(T, 2) + 1) * Integer::from(Integer::from(b - a).sqrt_ref());
           
        let x_a = &x - aa;

        let x_b = bb - &x;
        
        let x_a_1 = Integer::from(x_a.sqrt_ref());
        let x_a_2 = x_a - x_a_1.clone().pow(2);

        let x_b_1 = Integer::from(x_b.sqrt_ref());
        let x_b_2 = x_b - x_b_1.clone().pow(2);

        let mut boolean = true;
        let mut r_a_1 = Integer::from(1);
        let mut r_a_2 = Integer::from(1);
        while boolean {
            r_a_1 = rand_int(-Integer::from(2).pow(s) * Integer::from(2).pow(T) * n + Integer::from(1), Integer::from(2).pow(s) * Integer::from(2).pow(T) * n - Integer::from(1));
            r_a_2 = (&r - &r_a_1).complete();
            if -Integer::from(2).pow(s) * Integer::from(2).pow(T) * n + Integer::from(1) <= r_a_2 && r_a_2 <= Integer::from(2).pow(s) * Integer::from(2).pow(T) * n - Integer::from(1) && r == (&r_a_1 + &r_a_2).complete() {
                boolean = false;
            }
        }


        let mut r_b_1 = Integer::from(1);
        let mut r_b_2 = Integer::from(1);

        boolean = true;
        while boolean {
            r_b_1 = rand_int(-Integer::from(2).pow(s) * Integer::from(2).pow(T) * n + Integer::from(1), Integer::from(2).pow(s) * Integer::from(2).pow(T) * n - Integer::from(1));
            r_b_2 = (-Integer::from(1)) * &r - &r_b_1;
            if (-Integer::from(2).pow(s) * Integer::from(2).pow(T) * n + Integer::from(1) <= r_b_2 && r_b_2 <= Integer::from(2).pow(s) * Integer::from(2).pow(T) * n - Integer::from(1) && (-Integer::from(1)) * &r == (&r_b_1 + &r_b_2).complete()){
                boolean = false;
            }
        }


        let E_a_1 = (Integer::from(g.pow_mod_ref(&x_a_1.clone().pow(2), n).unwrap()) * Integer::from(h.pow_mod_ref(&r_a_1, n).unwrap())) % n;
        let E_a_2 = (Integer::from(g.pow_mod_ref(&x_a_2, n).unwrap()) * Integer::from(h.pow_mod_ref(&r_a_2, n).unwrap())) % n;

        let E_b_1 = (Integer::from(g.pow_mod_ref(&x_b_1.clone().pow(2), n).unwrap()) * Integer::from(h.pow_mod_ref(&r_b_1, n).unwrap())) % n;
        let E_b_2 = (Integer::from(g.pow_mod_ref(&x_b_2, n).unwrap()) * Integer::from(h.pow_mod_ref(&r_b_2, n).unwrap())) % n;
           
        let proof_of_square_a = Self::proof_of_square::<H>(&x_a_1, &r_a_1, g, h, &E_a_1, l, t, b, s, s1, s2, n);
        let proof_of_square_b = Self::proof_of_square::<H>(&x_b_1, &r_b_1, g, h, &E_b_1, l, t, b, s, s1, s2, n);
        let proof_large_i_a = Self::proof_large_interval_specific::<H>(&x_a_2, &r_a_2, g, h, t, l, b, s, n, T);
        let proof_large_i_b = Self::proof_large_interval_specific::<H>(&x_b_2, &r_b_2, g, h, t, l, b, s, n, T);
    
        // proof_wt = {
        //     'E_a_1': int(E_a_1), 'E_a_2': int(E_a_2), 'E_b_1': int(E_b_1), 'E_b_2': int(E_b_2),
        //     'proof_of_square_a': proof_of_square_a, 'proof_of_square_b': proof_of_square_b,
        //     'proof_large_i_a': proof_large_i_a, 'proof_large_i_b': proof_large_i_b
        // }

        ProofWt{E_a_1, E_a_2, E_b_1, E_b_2, proof_of_square_a, proof_of_square_b, proof_large_i_a, proof_large_i_b}
    
    }

    /* Algorithm 8 Verify Proof with Tolerance Specific factor 2 ** T */
    fn verify_of_tolerance_specific<H>(proof_wt: &ProofWt, g: &Integer, h: &Integer, E: &Integer, n: &Integer, a: &Integer, b: &Integer, t: u32, l: u32, T: u32) -> bool
    where
        H: Digest
    {

        let aa = Integer::from(2).pow(T) * Integer::from(a) - Integer::from(2).pow(l + t + rug::ops::DivRounding::div_floor(T, 2) + 1) * Integer::from(Integer::from(b - a).sqrt_ref());
        let bb = Integer::from(2).pow(T) * Integer::from(b) + Integer::from(2).pow(l + t + rug::ops::DivRounding::div_floor(T, 2) + 1) * Integer::from(Integer::from(b - a).sqrt_ref());
        let E_a = divm(E, &Integer::from(g.pow_mod_ref(&aa, n).unwrap()), n);
        let E_b = divm(&Integer::from(g.pow_mod_ref(&bb, n).unwrap()), E, n);
        // NOTE: E_a and E_b must be recomputed during the verification, 
        //        see Section 3.1.1 in [Boudot2000] ("Both Alice and Bob compute...")

        let ProofWt {E_a_1, E_a_2, E_b_1, E_b_2, proof_of_square_a, proof_of_square_b, proof_large_i_a, proof_large_i_b} = proof_wt;

        let div_a = divm(&E_a, E_a_1, n);
        let div_b = divm(&E_b, E_b_1, n);

        if E_a_2 == &div_a && E_b_2 == &div_b {
            let b_s = Self::verify_of_square::<H>(proof_of_square_a, g, h, n) && Self::verify_of_square::<H>(proof_of_square_b, g, h, n);
            let b_li = Self::verify_large_interval_specific::<H>(proof_large_i_a, E_a_2, g, h, n, t, l, b, T) && Self::verify_large_interval_specific::<H>(proof_large_i_b, E_b_2, g, h, n, t, l, b, T);
            return b_s && b_li
        }

        false

    }


    /* Algorithm 9 Square Decomposition Range Proof (i.e. Proof without tolerance) from [Boudot2000] on section 3.1.2 */
    fn proof_of_square_decomposition_range<H>(x: &Integer, r: &Integer, g: &Integer, h: &Integer, E: &Integer, n: &Integer, a: &Integer, b: &Integer, t: u32, l: u32, s: u32, s1: u32, s2: u32, T: u32) -> Self
    where
        H: Digest
    {
        let x_prime = Integer::from(2).pow(T) * x;
        let r_prime = Integer::from(2).pow(T) * r;

        let E_prime = Integer::from(E.pow_mod_ref(&(Integer::from(2).pow(T)), n).unwrap());

        let proof_of_tolerance = Self::proof_of_tolerance_specific::<H>(x_prime, r_prime, g, h, n, a, b, t, l, s, s1, s2, T);
    
        Self{proof_of_tolerance, E_prime, E: E.clone()}
    }

    
    /* Algorithm 10 Verify Square Decomposition Range Proof (i.e. Proof without tolerance) from [Boudot2000] on section 3.1.2 */
    fn verify_of_square_decomposition_range<H>(&self, g: &Integer, h: &Integer, n: &Integer, a: &Integer, b: &Integer, t: u32, l: u32, T: u32) -> bool
    where
        H: Digest
    {
        if self.E_prime == Integer::from(self.E.pow_mod_ref(&Integer::from(2).pow(T), n).unwrap()) {
            let res_verify_ts = Self::verify_of_tolerance_specific::<H>(&self.proof_of_tolerance, g, h, &self.E_prime, n, a, b, t, l, T);
            return res_verify_ts
        }
        return false
    }


    pub fn prove<H>(value: &Integer, commitment: &CL03Commitment, base1: &Integer, base2: &Integer, module: &Integer, rmin: &Integer, rmax: &Integer) -> Self
    where
        H: Digest
    {
        if rmax <= rmin{
            panic!("rmin > rmax");
        }

        let T = 2 * (Self::t + Self::l + 1) + ((rmax - rmin).complete().significant_bits());
        let proof_of_sdr = Self::proof_of_square_decomposition_range::<H>(value, &commitment.randomness, base1, base2, &commitment.value, module, rmin, rmax, Self::t, Self::l, Self::s, Self::s1, Self::s2, T);
        proof_of_sdr
    }

    pub fn verify<H>(&self, base1: &Integer, base2: &Integer, module: &Integer, rmin: &Integer, rmax: &Integer) -> bool
    where
        H: Digest
    {
        if rmax <= rmin{
            panic!("rmin > rmax");
        }

        let T = 2 * (Self::t + Self::l + 1) + ((rmax - rmin).complete().significant_bits());

        let valid = Self::verify_of_square_decomposition_range::<H>(self, base1, base2, module, rmin, rmax, Self::t, Self::l, T);
        valid
    }
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum RangeProof{
    Boudot2000,
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct NISP2Commitments {
    challenge: Integer,
    d: Vec<Integer>,
    d_1: Integer,
    d_2: Integer
}

impl NISP2Commitments {
    /* Generation of the proof related to two commitments (C1 and C2) (generate proof that C1 is a commitment to the same secrets as C2) */
    pub(crate) fn nisp2_generate_proof_MultiSecrets<CS>(messages: &[CL03Message], c1: &CL03Commitment, c2: &CL03Commitment, signer_pk: &CL03PublicKey, commitment_pk: &CL03CommitmentPublicKey, unrevealed_message_indexes: &[usize]) -> Self
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest
    {
        let n_attr = messages.len();

        if signer_pk.a_bases.len() < n_attr  && n_attr < commitment_pk.g_bases.len(){
            panic!("Not enough a_bases OR g_bases for the number of attributes");
        }

        let h1 = &signer_pk.b;
        let n1 = &signer_pk.N;
        let h2 = &commitment_pk.h;
        let n2 = &commitment_pk.N;

        // Initialize multiple random values, equivalent to secrets m_i and stored in a list
        let mut omega: Vec<Integer> = Vec::new();
        for i in unrevealed_message_indexes{ 
            omega.push(random_bits(CS::lm));
        }

        let mu_1 = random_bits(CS::ln);
        let mu_2 = random_bits(CS::ln);

        let mut w_1 = Integer::from(1);
        let mut w_2 = Integer::from(1);
        let mut idx = 0usize;


        for i in unrevealed_message_indexes {
            w_1 = w_1 * (Integer::from(signer_pk.a_bases.get(*i).expect("unrevealed_message_indexes not valid (overflow)").0.pow_mod_ref(&omega[idx], n1).unwrap()));
            w_2 = w_2 * (Integer::from(commitment_pk.g_bases.get(*i).expect("unrevealed_message_indexes not valid (overflow)").0.pow_mod_ref(&omega[idx], n2).unwrap()));
            idx = idx + 1;
        }
        w_1 = (w_1 * Integer::from(h1.pow_mod_ref(&mu_1, n1).unwrap())) % n1;
        w_2 = (w_2 * Integer::from(h2.pow_mod_ref(&mu_2, n2).unwrap())) % n2;


        let str =  w_1.to_string() + &w_2.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);


        let mut d: Vec<Integer> = Vec::new();
        let mut idx = 0usize;

        for i in unrevealed_message_indexes {
            d.push((&omega[idx] + &challenge * &messages.get(*i).expect("unrevealed_message_indexes not valid (overflow)").value).complete());
            idx = idx + 1;
        }

        let d_1 = mu_1 + &challenge * &c1.randomness;
        let d_2 = mu_2 + &challenge * &c2.randomness;

        Self{challenge, d, d_1 ,d_2}

    }

    /* Verification of the proof for two commitments (C1 and C2) */
    pub(crate) fn nisp2_verify_proof_MultiSecrets<CS>(&self, c1: &CL03Commitment, c2: &CL03Commitment, signer_pk: &CL03PublicKey, commitment_pk: &CL03CommitmentPublicKey, unrevealed_message_indexes: &[usize]) -> bool
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest
    {

        let h1 = &signer_pk.b;
        let n1 = &signer_pk.N;
        let h2 = &commitment_pk.h;
        let n2 = &commitment_pk.N;


        let Self{challenge, d, d_1, d_2} = self;

        let inv_C1 = Integer::from(c1.value.pow_mod_ref(&(-Integer::from(1) * challenge), n1).unwrap());
        let inv_C2 = Integer::from(c2.value.pow_mod_ref(&(-Integer::from(1) * challenge), n2).unwrap());


        let mut lhs = Integer::from(1);
        let mut rhs = Integer::from(1);
        let mut idx = 0usize;

        for i in unrevealed_message_indexes {
            lhs = lhs * Integer::from(signer_pk.a_bases.get(*i).expect("unrevealed_message_indexes not valid (overflow)").0.pow_mod_ref(&d[idx], n1).unwrap());
            rhs = rhs * Integer::from(commitment_pk.g_bases.get(*i).expect("unrevealed_message_indexes not valid (overflow)").0.pow_mod_ref(&d[idx], n2).unwrap());
            idx += 1;
        }
        // lhs = ((lhs * powmod(h1, d_1, n1)) * inv_C1) % n1  
        // rhs = ((rhs * powmod(h2, d_2, n2)) * inv_C2) % n2 
        lhs = ((lhs * Integer::from(h1.pow_mod_ref(d_1, n1).unwrap())) * inv_C1) % n1;
        rhs = ((rhs * Integer::from(h2.pow_mod_ref(d_2, n2).unwrap())) * inv_C2) % n2;

        let str =  lhs.to_string() + &rhs.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str);
        let output = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        challenge == &output

    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct NISPSecrets{
    t: Integer,
    s1: Integer,
    s2: Integer
}

impl NISPSecrets {
    fn nisp2sec_generate_proof<CS>(message: &CL03Message, commitment: &CL03Commitment, g1: &Integer, h1: &Integer, n1: &Integer) -> Self
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest
    {
        let r1 = random_bits(CS::lm);
        let r2 = random_bits(CS::ln);

        let t = (Integer::from(g1.pow_mod_ref(&r1, &n1).unwrap()) * Integer::from(h1.pow_mod_ref(&r2, &n1).unwrap())) % n1;
        let str_input = g1.to_string() + &h1.to_string() + &commitment.value.to_string() + &t.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str_input);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let s1 = r1 + (&challenge * &message.value);
        let s2 = r2 + (&challenge * &commitment.randomness);

        Self{t, s1, s2}

    }

    fn nisp2sec_verify_proof<CS>(&self, commitment: &CL03Commitment, g1: &Integer, h1: &Integer, n1: &Integer) -> bool
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest
    {
        let Self{t, s1, s2} = self;
        let lhs = (Integer::from(g1.pow_mod_ref(s1, &n1).unwrap()) * Integer::from(h1.pow_mod_ref(s2, &n1).unwrap())) % n1;
        let str_input = g1.to_string() + &h1.to_string() + &commitment.value.to_string() + &t.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str_input);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let rhs = (t * Integer::from(commitment.value.pow_mod_ref(&challenge, &n1).unwrap())) % n1;

        lhs == rhs
    }
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct NISPMultiSecrets {
    t: Integer,
    s1: Vec<Integer>,
    s2: Integer
}

impl NISPMultiSecrets {

    /* Generation of the proof related to multiple secrets (x and r) */
    fn nispMultiSecrets_generate_proof<CS>(messages: &[CL03Message], commitment: &CL03Commitment, signer_pk: &CL03PublicKey, unrevealed_message_indexes: Option<&[usize]>) -> Self
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest
    {
        let mut unrevealed_message_indexes = unrevealed_message_indexes.unwrap_or(&[0]);
        // Initialize multiple random values, equivalent to secrets m_i and stored in a list

        if messages.len() == 1 {
            unrevealed_message_indexes = &[0];
        }

        let mut r1: Vec<Integer> = Vec::new();
        for _ in unrevealed_message_indexes {
            r1.push(random_bits(CS::lm));
        }

        let r2 = random_bits(CS::ln);

        let h1 = &signer_pk.b;
        let n1 = &signer_pk.N;

        let mut t = Integer::from(1);
        let mut str_input = String::from("");
        let mut idx = 0usize;
        for i in unrevealed_message_indexes {
            t = t * Integer::from(signer_pk.a_bases.get(*i).expect("unrevealed_message_indexes not valid (overflow)").0.pow_mod_ref(&r1[idx], n1).unwrap());
            str_input = str_input + &signer_pk.a_bases[*i].0.to_string();
            idx += 1;
        }
        t = (t * Integer::from(h1.pow_mod_ref(&r2, n1).unwrap())) % n1; 

        str_input = str_input + &h1.to_string() + &commitment.value.to_string() + &t.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str_input);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let mut s1: Vec<Integer> = Vec::new();
        idx = 0usize;

        for i in unrevealed_message_indexes {
            s1.push((&r1[idx] + &challenge * &messages.get(*i).expect("unrevealed_message_indexes not valid (overflow)").value).complete());
            idx += 1;
        }
        let s2 = r2 + (challenge * &commitment.randomness);

        Self{t, s1, s2}
        
        //NOTE: s1 is a list with number_of_secrets values
   
    }

    fn nispMultiSecrets_verify_proof<CS>(&self, commitment: &CL03Commitment, signer_pk: &CL03PublicKey, unrevealed_message_indexes: Option<&[usize]>) -> bool
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest
    {
        let unrevealed_message_indexes = unrevealed_message_indexes.unwrap_or(&[0]);

        let h1 = &signer_pk.b;
        let n1 = &signer_pk.N;
        let Self{t, s1, s2} = self;

        if unrevealed_message_indexes.len() != s1.len() {
            panic!("unrevealed_message_indexes not valid");
        }

        let mut lhs = Integer::from(1);
        let mut str_input = String::from("");
        let mut idx = 0usize;

        for i in unrevealed_message_indexes {
            lhs = lhs * Integer::from(signer_pk.a_bases.get(*i).expect("unrevealed_message_indexes not valid (overflow)").0.pow_mod_ref(&s1[idx], n1).unwrap());
            str_input = str_input + &signer_pk.a_bases[*i].0.to_string();
            idx += 1;
        }
        lhs = (lhs * Integer::from(h1.pow_mod_ref(&s2, n1).unwrap())) % n1;
        str_input = str_input + &h1.to_string() + &commitment.value.to_string() + &t.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str_input);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let rhs = (t * Integer::from(commitment.value.pow_mod_ref(&challenge, n1).unwrap())) % n1;
        
        lhs == rhs

    }

    
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusZKPoK {
    c: Scalar, 
    s_cap: Scalar,
    r_cap: Vec<Scalar>
}

impl BBSplusZKPoK {

    fn blindMessagesProofGen<CS>(unrevealed_messages: &[BBSplusMessage], commitment: &BBSplusCommitment, generators: &Generators, unrevealed_message_indexes: &[usize], nonce: &[u8]) -> Self
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        if generators.message_generators.len() < *unrevealed_message_indexes.iter().max().unwrap_or(&0)  && unrevealed_messages.len() != unrevealed_message_indexes.len(){
            panic!("len(generators) < max(unrevealed_message_indexes) || len(unrevealed_messages) != len(unrevealed_message_indexes)");
        }

        // Get unrevealed messages length
        let U = unrevealed_message_indexes.len();

        //  (i1,...,iU) = CGIdxs = unrevealed_indexes
			
		//  s~ = HASH(PRF(8 * ceil(log2(r)))) mod
        let s_tilde = calculate_random_scalars::<CS>(1, None)[0];
		//  r~ = [U]
		//  for i in 1 to U: r~[i] = HASH(PRF(8 * ceil(log2(r)))) mod r
        let r_tilde = calculate_random_scalars::<CS>(U, None);	
		//  U~ = h0 * s~ + h[i1] * r~[1] + ... + h[iU] \* r~[U]
        let mut U_tilde = generators.q1 * s_tilde;	


        let mut index = 0usize;
        for i in unrevealed_message_indexes {
            U_tilde += generators.message_generators.get(*i).expect("unreaveled_message_indexes not valid (overflow)") * r_tilde.get(index).expect("index buffer overflow");
            index += 1;
        }

        // c = HASH(commitment || U~ || nonce)

        let mut value: Vec<u8> = Vec::new();
        value.extend_from_slice(&commitment.value.to_affine().to_compressed());
        value.extend_from_slice(&U_tilde.to_affine().to_compressed());
        value.extend_from_slice(nonce);
        
        let c = hash_to_scalar_old::<CS>(&value, 1, None)[0];
		// TODO update hash_to_scalar as in latest draft	

		// s^ = s~ + c * s'
        let s_cap = s_tilde + c * commitment.s_prime;
		
		// for i in 1 to U: r^[i] = r~[i] + c * msg[i]

        let mut r_cap: Vec<Scalar> = Vec::new();
        for index in 0..U {
            r_cap.push(r_tilde.get(index).expect("index buffer overflow") + c * unrevealed_messages.get(index).expect("index buffer overflow").value);
        }		
		// nizk = (c, s^, r^)
        Self{c, s_cap, r_cap}
		// nizk = [c, s_cap] + r_cap
    }

    fn blindMessagesProofVerify<CS>(&self, commitment: &BBSplusCommitment, generators: &Generators, unrevealed_message_indexes: &[usize], nonce: &[u8]) -> bool
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {

        if generators.message_generators.len() < *unrevealed_message_indexes.iter().max().unwrap_or(&0) {
            panic!("len(generators) < max(unrevealed_message_indexes)");
        }
        // Get unrevealed messages length
        let U = unrevealed_message_indexes.len();
        // (i1,...,iU) = CGIdxs = unrevealed_indexes

        // U^ = commitment * -c + h0 * s^ + h[i1] \* r^[1] + ... + h[iU] \* r^[U]
        let mut U_cap = commitment.value * (-self.c) + generators.q1 * self.s_cap;
        let mut index = 0usize;

        for i in unrevealed_message_indexes {
            U_cap += generators.message_generators.get(*i).expect("unrevealed_message_indexes not valid") * self.r_cap.get(index).expect("index overflow");
            index += 1;
        }
        // c_v = HASH(U || U^ || nonce)
        let mut value: Vec<u8> = Vec::new();
        value.extend_from_slice(&commitment.value.to_affine().to_compressed());
        value.extend_from_slice(&U_cap.to_affine().to_compressed());
        value.extend_from_slice(nonce);

        let cv = hash_to_scalar_old::<CS>(&value, 1, None)[0]; //TODO: update hash_to_scalar as in latest draft	

        self.c == cv
    }

}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03ZKPoK {
    proof_C_Ctrusted: Option<NISP2Commitments>,
    proof_commited_msgs: NISPMultiSecrets,
    proofs_commited_mi: Vec<ProofOfValue>,
    range_proofs_mi: Vec<Boudot2000RangeProof>,
    proof_r: ProofOfValue,
    range_proof_r: Boudot2000RangeProof
}

impl CL03ZKPoK {

}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ZKPoK<S: Scheme> {
    BBSplus(BBSplusZKPoK),
    CL03(CL03ZKPoK),
    _Unreachable(PhantomData<S>)
}


impl <CS: BbsCiphersuite> ZKPoK<BBSplus<CS>>  
{
    pub fn generate_proof(unrevealed_messages: &[BBSplusMessage], commitment: &BBSplusCommitment, generators: &Generators, unrevealed_message_indexes: &[usize], nonce: &[u8]) -> Self
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        Self::BBSplus(BBSplusZKPoK::blindMessagesProofGen::<CS>(unrevealed_messages, commitment, generators, unrevealed_message_indexes, nonce))
    }

    pub fn verify_proof(&self, commitment: &BBSplusCommitment, generators: &Generators, unrevealed_message_indexes: &[usize], nonce: &[u8]) -> bool 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        self.to_bbsplus_zkpok().blindMessagesProofVerify::<CS>(commitment, generators, unrevealed_message_indexes, nonce)
    }

    pub fn to_bbsplus_zkpok(&self) -> &BBSplusZKPoK {
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn to_bytes(&self) {
        todo!()
    }

    pub fn from_bytes() {
        todo!()
    }
}


impl <CS: CLCiphersuite> ZKPoK<CL03<CS>> {
    pub fn generate_proof(messages: &[CL03Message], C: &CL03Commitment, C_trusted: Option<&CL03Commitment>, signer_pk: &CL03PublicKey, commitment_pk: Option<&CL03CommitmentPublicKey>, unrevealed_message_indexes: &[usize]) -> Self
    where
        CS::HashAlg: Digest
    {
        let mut proof_C_Ctrusted: Option<NISP2Commitments> = None;
        if let Some(C_trusted) = C_trusted {
            if let Some(commitment_pk) = commitment_pk {
                proof_C_Ctrusted = Some(NISP2Commitments::nisp2_generate_proof_MultiSecrets::<CS>(
                    messages,
                    C,
                    &C_trusted,
                    signer_pk,
                    commitment_pk,
                    unrevealed_message_indexes,
                ));
            }
        }

        
        let proof_msgs = NISPMultiSecrets::nispMultiSecrets_generate_proof::<CS>(messages, C, signer_pk, Some(unrevealed_message_indexes));
        
        let min_x = Integer::from(0);  
        let max_x = Integer::from(2).pow(CS::lm) - 1;
        //RANGE PROOF on unrevealde messages
        let mut proofs_mi: Vec<ProofOfValue> = Vec::new();
        let mut r_proofs_msgs: Vec<Boudot2000RangeProof> = Vec::new();
        for i in unrevealed_message_indexes {
            let mi = messages.get(*i).expect("unreaveled_message_indexes not valid with respect to the messages!");
            let ai = &signer_pk.a_bases.get(*i).expect("unreaveled_message_indexes not valid with respect to the commitment_pk.g_bases!").0;
            let cmi = Commitment::<CL03<CS>>::commit_with_pk(&[mi.clone()], signer_pk, None).cl03Commitment().to_owned();
            let proof_mi = NISPSecrets::nisp2sec_generate_proof::<CS>(mi, &cmi, &ai, &signer_pk.b, &signer_pk.N);
            proofs_mi.push(ProofOfValue { value: proof_mi, commitment: cmi.clone()});
            match CS::RANGEPROOF_ALG {
                RangeProof::Boudot2000 => {
                    let r_proof_mi = Boudot2000RangeProof::prove::<CS::HashAlg>(&mi.value, &cmi, &ai, &signer_pk.b, &signer_pk.N, &min_x, &max_x);
                    r_proofs_msgs.push(r_proof_mi);
                },
            };
        }

        //RANGE PROOF on randomness of C
        let min_r = Integer::from(0);  
        let max_r = Integer::from(2).pow(CS::ln) - 1;
        let r = CL03Message::new(C.randomness.clone());
        let cr = Commitment::<CL03<CS>>::commit_with_pk(&[r.clone()], &signer_pk, None);
        let proof_r = ProofOfValue{value: NISPSecrets::nisp2sec_generate_proof::<CS>(&r, cr.cl03Commitment(), &signer_pk.a_bases[0].0, &signer_pk.b, &signer_pk.N), commitment: cr.cl03Commitment().to_owned()};

        let rproof_r = match CS::RANGEPROOF_ALG {
            RangeProof::Boudot2000 => Boudot2000RangeProof::prove::<CS::HashAlg>(&r.value, cr.cl03Commitment(), &signer_pk.a_bases[0].0, &signer_pk.b, &signer_pk.N, &min_r, &max_r),
        };


        Self::CL03(CL03ZKPoK{proof_C_Ctrusted, proof_commited_msgs: proof_msgs, proofs_commited_mi: proofs_mi, range_proofs_mi: r_proofs_msgs, proof_r: proof_r, range_proof_r: rproof_r})
    }

    pub fn verify_proof(&self, C: &CL03Commitment, C_trusted: Option<&CL03Commitment>, signer_pk: &CL03PublicKey, commitment_pk: Option<&CL03CommitmentPublicKey>, unrevealed_message_indexes: &[usize]) -> bool
    where
        CS::HashAlg: Digest
    {
        let zkpok = self.to_cl03_zkpok();

        let mut boolean_C_Ctrusted: bool = true;
        if let Some(C_trusted) = C_trusted {
            if let Some(commitment_pk) = commitment_pk {
                boolean_C_Ctrusted = zkpok.proof_C_Ctrusted.clone().unwrap().nisp2_verify_proof_MultiSecrets::<CS>(C, C_trusted, signer_pk, commitment_pk, unrevealed_message_indexes);
            }
        }

        if !boolean_C_Ctrusted {
            println!("The trusted commitment is different from commitment received!");
            return false;
        } 

        
        let boolean_proof_msgs = zkpok.proof_commited_msgs.nispMultiSecrets_verify_proof::<CS>(C, signer_pk, Some(unrevealed_message_indexes));
        
        if !boolean_proof_msgs {
            println!("Verification of the PoK of secrets Failed!");
            return false;
        }

        let min_x = Integer::from(0);  
        let max_x = Integer::from(2).pow(CS::lm) - 1;
        let mut idx = 0usize;

        for i in unrevealed_message_indexes {
            let ai = &signer_pk.a_bases.get(*i).expect("unreaveled_message_indexes not valid with respect to the messages!").0;
            let proof_mi = zkpok.proofs_commited_mi.get(idx).expect("index overflow");
            let boolean_proof_mi = proof_mi.value.nisp2sec_verify_proof::<CS>(&proof_mi.commitment, ai, &signer_pk.b, &signer_pk.N);

            if !boolean_proof_mi {
                println!("Verification of the Proof of Knowledge of m{}. Failed!", i);
                return false;
            }
            let rproof_mi = zkpok.range_proofs_mi.get(idx).expect("index overflow");
            let boolean_rproof_mi = rproof_mi.verify::<CS::HashAlg>(&ai, &signer_pk.b, &signer_pk.N,&min_x, &max_x);
            if !boolean_rproof_mi {
                println!("Verification of the Range Proof of m{}. Failed", i);
                return false;
            }

            idx += 1;
        }

        let boolean_proof_r = zkpok.proof_r.value.nisp2sec_verify_proof::<CS>(&zkpok.proof_r.commitment, &signer_pk.a_bases[0].0, &signer_pk.b, &signer_pk.N);
        if !boolean_proof_r {
            println!("Verification of the Proof of Knowledge of r. Failed!");
            return false;
        }

        let min_r = Integer::from(0);  
        let max_r = Integer::from(2).pow(CS::ln) - 1;
        let boolean_rproof_r = zkpok.range_proof_r.verify::<CS::HashAlg>(&signer_pk.a_bases[0].0, &signer_pk.b, &signer_pk.N, &min_r, &max_r);
        if !boolean_rproof_r {
            println!("Verification of the Range Proof of r. Failed");
            return false;
        }

        true
    }

    pub fn to_cl03_zkpok(&self) -> &CL03ZKPoK {
        match self {
            Self::CL03(inner) => &inner,
            _ => panic!("Cannot happen!")
        }
    }
}