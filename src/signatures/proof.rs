use std::marker::PhantomData;

use bls12_381_plus::{G1Projective, Scalar, G2Projective, G2Prepared, Gt, multi_miller_loop, G1Affine};
use digest::Digest;
use elliptic_curve::{hash2curve::ExpandMsg, group::Curve};
use rug::{Integer, ops::Pow};
use serde::{Serialize, Deserialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, utils::message::{BBSplusMessage, CL03Message}, bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, cl03::{ciphersuites::CLCiphersuite, sigma_protocols::{NISPSecrets, NISP2Commitments, NISPMultiSecrets, NISPSignaturePoK}, range_proof::{Boudot2000RangeProof, RangeProof}}, keys::{bbsplus_key::BBSplusPublicKey, cl03_key::{CL03CommitmentPublicKey, CL03PublicKey}}, utils::util::{get_remaining_indexes, get_messages, calculate_domain, calculate_random_scalars, ScalarExt, hash_to_scalar_old}};

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

        let domain = calculate_domain::<CS>(pk, generators.q1, generators.q2, &generators.message_generators[0..L], Some(header));

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
            if *i > L {
                panic!("i >= L");
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
            H_i.push(*generators.message_generators.get(*idx).expect("index overflow"));
        }

        let mut H_j: Vec<G1Projective> = Vec::new();

        for idx in unrevealed_message_indexes {
            H_j.push(*generators.message_generators.get(idx).expect("index overflow"));
        }

        let domain = calculate_domain::<CS>(pk, generators.q1, generators.q2, &generators.message_generators[0..L], Some(header));

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

    pub fn from_bytes(bytes: &[u8]) -> Self{
        
        let len = bytes.len();
        if len < 304 || (len - 304) % 32 != 0 {
            panic!("Invalid number of bytes submitted!");
        }

        let A_prime =  G1Affine::from_compressed(&<[u8; 48]>::try_from(&bytes[0..48]).unwrap())
        .map(G1Projective::from).unwrap();
        let A_bar = G1Affine::from_compressed(&<[u8; 48]>::try_from(&bytes[48..96]).unwrap())
        .map(G1Projective::from).unwrap();
        let D = G1Affine::from_compressed(&<[u8; 48]>::try_from(&bytes[96..144]).unwrap())
        .map(G1Projective::from).unwrap();


        let c = Scalar::from_bytes_be(&<[u8; 32]>::try_from(&bytes[144..176]).unwrap());

        let e_cap = Scalar::from_bytes_be(&<[u8; 32]>::try_from(&bytes[176..208]).unwrap());
        let r2_cap = Scalar::from_bytes_be(&<[u8; 32]>::try_from(&bytes[208..240]).unwrap());
        let r3_cap = Scalar::from_bytes_be(&<[u8; 32]>::try_from(&bytes[240..272]).unwrap());
        let s_cap = Scalar::from_bytes_be(&<[u8; 32]>::try_from(&bytes[272..304]).unwrap());
        let mut start = 304;
        let mut end = start + 32;
        let mut m_cap: Vec<Scalar> = Vec::new();


        while end <= len {
            let b = <[u8; 32]>::try_from(&bytes[start..end]);
            if b.is_err() {
                panic!("bytes not valid");
            } else {
                m_cap.push(Scalar::from_bytes_be(&b.unwrap()));
            }
            start = end;
            end += 32;
        }

        Self::BBSplus(BBSplusPoKSignature { A_prime, A_bar, D, c, e_cap, r2_cap, r3_cap, s_cap, m_cap })
        
        
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
            RangeProof::Boudot2000 => Boudot2000RangeProof::prove::<CS::HashAlg>(&signature.e, &spok.Ce, &commitment_pk.g_bases[0], &commitment_pk.h, &commitment_pk.N, &min_e, &max_e),
        };

        let mut proofs_mi: Vec<ProofOfValue> = Vec::new();
        let mut r_proofs_mi: Vec<Boudot2000RangeProof> = Vec::new();
        for i in unrevealed_message_indexes {
            let mi = messages.get(*i).expect("unreaveled_message_indexes not valid with respect to the messages!");
            let gi = &commitment_pk.g_bases.get(*i).expect("unreaveled_message_indexes not valid with respect to the commitment_pk.g_bases!");
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
            let boolean_rproof_e = CLSPoK.range_proof_e.verify::<CS::HashAlg>(&commitment_pk.g_bases[0], &commitment_pk.h, &commitment_pk.N, &min_e, &max_e);
            
            if boolean_rproof_e {
                //Verify RANGE PROOFS mi
                let mut idx: usize = 0;
                for i in unrevealed_message_indexes {
                    
                    let gi = &commitment_pk.g_bases.get(*i).expect("unreaveled_message_indexes not valid with respect to the commitment_pk.g_bases!");
                    let ProofOfValue{value: proof_mi, commitment: cmi} = CLSPoK.proofs_commited_mi.get(idx).expect("index overflow");
                    let boolean_proof_mi = proof_mi.nisp2sec_verify_proof::<CS>(&cmi, gi, &commitment_pk.h, &commitment_pk.N);
                    if !boolean_proof_mi {
                        println!("Knowledge verification of mi Failed!");
                        return false;
                    }
                    let boolean_rproofs_mi = CLSPoK.range_proofs_commited_mi.get(idx).expect("index overflow").verify::<CS::HashAlg>(&gi, &commitment_pk.h, &commitment_pk.N, &min_x, &max_x);
                    if !boolean_rproofs_mi {
                        println!("Range proof verification on mi Failed!");
                        return false;
                    }
                    idx += 1;
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
        // let U = unrevealed_message_indexes.len();
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

impl CL03ZKPoK {}

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
            let ai = &signer_pk.a_bases.get(*i).expect("unreaveled_message_indexes not valid with respect to the commitment_pk.g_bases!");
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
        let proof_r = ProofOfValue{value: NISPSecrets::nisp2sec_generate_proof::<CS>(&r, cr.cl03Commitment(), &signer_pk.a_bases[0], &signer_pk.b, &signer_pk.N), commitment: cr.cl03Commitment().to_owned()};

        let rproof_r = match CS::RANGEPROOF_ALG {
            RangeProof::Boudot2000 => Boudot2000RangeProof::prove::<CS::HashAlg>(&r.value, cr.cl03Commitment(), &signer_pk.a_bases[0], &signer_pk.b, &signer_pk.N, &min_r, &max_r),
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
            let ai = &signer_pk.a_bases.get(*i).expect("unreaveled_message_indexes not valid with respect to the messages!");
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

        let boolean_proof_r = zkpok.proof_r.value.nisp2sec_verify_proof::<CS>(&zkpok.proof_r.commitment, &signer_pk.a_bases[0], &signer_pk.b, &signer_pk.N);
        if !boolean_proof_r {
            println!("Verification of the Proof of Knowledge of r. Failed!");
            return false;
        }

        let min_r = Integer::from(0);  
        let max_r = Integer::from(2).pow(CS::ln) - 1;
        let boolean_rproof_r = zkpok.range_proof_r.verify::<CS::HashAlg>(&signer_pk.a_bases[0], &signer_pk.b, &signer_pk.N, &min_r, &max_r);
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