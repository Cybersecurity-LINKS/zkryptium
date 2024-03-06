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


use std::ops::Deref;

use bls12_381_plus::{G1Projective, Scalar, G2Projective, G2Prepared, Gt, multi_miller_loop, G1Affine};
use elliptic_curve::{group::Curve, hash2curve::ExpandMsg, Group};
use serde::{Serialize, Deserialize};
use crate::{bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, errors::Error, schemes::{algorithms::BBSplus, generics::{PoKSignature, ZKPoK}}, utils::{message::BBSplusMessage, util::{bbsplus_utils::{calculate_domain_new, get_messages, get_random, hash_to_scalar_new, hash_to_scalar_old, i2osp, ScalarExt}, get_remaining_indexes}}};
use super::{signature::BBSplusSignature, keys::BBSplusPublicKey, commitment::BBSplusCommitment};


#[cfg(not(test))]
use crate::utils::util::bbsplus_utils::calculate_random_scalars;
#[cfg(test)]
use crate::utils::util::bbsplus_utils::seeded_random_scalars;


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusPoKSignature{
    Abar: G1Projective,
    Bbar: G1Projective,
    D: G1Projective,
    e_cap: Scalar,
    r1_cap: Scalar,
    r3_cap: Scalar,
    m_cap: Vec<Scalar>,
    challenge: Scalar,
}

impl BBSplusPoKSignature {

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.Abar.to_affine().to_compressed());
        bytes.extend_from_slice(&self.Bbar.to_affine().to_compressed());
        bytes.extend_from_slice(&self.D.to_affine().to_compressed());
        bytes.extend_from_slice(&self.e_cap.to_bytes_be());
        bytes.extend_from_slice(&self.r1_cap.to_bytes_be());
        bytes.extend_from_slice(&self.r3_cap.to_bytes_be());
        self.m_cap.iter().for_each(|v| bytes.extend_from_slice(&v.to_bytes_be()));
        bytes.extend_from_slice(&self.challenge.to_bytes_be());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let parse_g1_affine = |slice: &[u8]| -> Result<G1Projective, Error> {
            let point = G1Affine::from_compressed(&<[u8; 48]>::try_from(slice).map_err(|_| Error::InvalidProofOfKnowledgeSignature)?);
            if point.is_none().into() {
                return Err(Error::InvalidProofOfKnowledgeSignature);
            }
            Ok(point.map(G1Projective::from).unwrap())
        };
    
        let Abar = parse_g1_affine(&bytes[0..48])?;
        let Bbar = parse_g1_affine(&bytes[48..96])?;
        let D = parse_g1_affine(&bytes[96..144])?;
    
        let e_cap = Scalar::from_bytes_be(&<[u8; 32]>::try_from(&bytes[144..176]).map_err(|_| Error::InvalidProofOfKnowledgeSignature)?);
        let r1_cap = Scalar::from_bytes_be(&<[u8; 32]>::try_from(&bytes[176..208]).map_err(|_| Error::InvalidProofOfKnowledgeSignature)?);
        let r3_cap = Scalar::from_bytes_be(&<[u8; 32]>::try_from(&bytes[208..240]).map_err(|_| Error::InvalidProofOfKnowledgeSignature)?);
    
        let mut m_cap: Vec<Scalar> = Vec::new();
    
        for chunk in bytes[240..].chunks_exact(32) {
            let b = <[u8; 32]>::try_from(chunk).map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
            m_cap.push(Scalar::from_bytes_be(&b));
        }

        let challenge = m_cap.pop().ok_or(Error::InvalidProofOfKnowledgeSignature)?; //at least the challenge should be present (even if all attributes are disclosed)

        Ok(Self { Abar, Bbar, D, e_cap, r1_cap, r3_cap, m_cap, challenge })
    }
}





impl <CS: BbsCiphersuite> PoKSignature<BBSplus<CS>> {

    pub fn proof_gen(signature: &BBSplusSignature, pk: &BBSplusPublicKey, messages: Option<&[Vec<u8>]>, disclosed_indexes: Option<&[usize]>, header: Option<&[u8]>, ph: Option<&[u8]>) -> Result<Self, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let messages = messages.unwrap_or(&[]);
        let disclosed_indexes = disclosed_indexes.unwrap_or(&[]);

        let message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID)?;
        let generators = Generators::create::<CS>(messages.len()+1);

        let proof = core_proof_gen::<CS>(
            pk, 
            signature, 
            &generators, 
            &message_scalars, 
            disclosed_indexes, 
            header, 
            ph, 
            Some(CS::API_ID)
        )?;

        Ok(Self::BBSplus(proof))
    }

    pub fn proof_verify(&self, pk: &BBSplusPublicKey, disclosed_messages: Option<&[Vec<u8>]>, disclosed_indexes: Option<&[usize]>, header: Option<&[u8]>, ph: Option<&[u8]>) -> Result<(), Error> 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let proof = self.to_bbsplus_proof();

        let disclosed_messages = disclosed_messages.unwrap_or(&[]);
        let mut disclosed_indexes = disclosed_indexes.unwrap_or(&[]).to_vec();
        disclosed_indexes.sort();
        disclosed_indexes.dedup();

        let U = proof.m_cap.len();
        let R = disclosed_indexes.len();

        let disclosed_message_scalars = BBSplusMessage::messages_to_scalar::<CS>(disclosed_messages, CS::API_ID)?;

        let generators = Generators::create::<CS>(U + R + 1);

        let result = core_proof_verify::<CS>(
            pk, 
            proof, 
            &generators, 
            header, 
            ph,
            &disclosed_message_scalars, 
            &disclosed_indexes, 
            Some(CS::API_ID)
        );

        result
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
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bbsplus_proof().to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusPoKSignature::from_bytes(bytes)?))  
    }

    pub fn to_bbsplus_proof(&self) ->  &BBSplusPoKSignature {
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }
}


fn core_proof_gen<CS>(pk: &BBSplusPublicKey, signature: &BBSplusSignature, generators: &Generators, messages: &[BBSplusMessage], disclosed_indexes: &[usize], header: Option<&[u8]>, ph: Option<&[u8]>, api_id: Option<&[u8]>) -> Result<BBSplusPoKSignature, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let L = messages.len();
    let mut disclosed_indexes = disclosed_indexes.to_vec();
    disclosed_indexes.sort();
    disclosed_indexes.dedup();
    
    let R = disclosed_indexes.len();
    if R > L {
        return Err(Error::ProofGenError("R > L".to_owned()))
    }
    let U = L - R;

    if let Some(invalid_index) = disclosed_indexes.iter().find(|&&i| i > L - 1) {
        return Err(Error::ProofGenError(format!("Invalid disclosed index: {}", invalid_index)));
    }

    let undisclosed_indexes: Vec<usize> = get_remaining_indexes(L, &disclosed_indexes);

    let disclosed_messages = get_messages(messages, &disclosed_indexes);
    let undisclosed_messages = get_messages(messages, &undisclosed_indexes);
  
    #[cfg(not(test))]
    let random_scalars = calculate_random_scalars(5 + U);

    #[cfg(test)]
    let random_scalars = seeded_random_scalars::<CS>(5 + U, None, None);

    let init_res = proof_init::<CS>(
        pk, 
        signature, 
        generators, 
        &random_scalars, 
        header, 
        messages, 
        &undisclosed_indexes, 
        api_id
    )?;

    let challenge = proof_challenge_calculate::<CS>(
        &init_res, 
        &disclosed_indexes,
        &disclosed_messages, 
        ph,
        api_id
    )?;

    let proof = proof_finalize(
        &init_res, 
        challenge, 
        signature.e, 
        &random_scalars,
        &undisclosed_messages
    )?;

    Ok(proof)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ProofInitResult {
    Abar: G1Projective, 
    Bbar: G1Projective, 
    D: G1Projective, 
    T1: G1Projective, 
    T2: G1Projective,
    domain: Scalar
}

fn proof_init<CS>(pk: &BBSplusPublicKey, signature: &BBSplusSignature, generators: &Generators, random_scalars: &[Scalar], header: Option<&[u8]>, messages: &[BBSplusMessage], undisclosed_indexes: &[usize], api_id: Option<&[u8]>) -> Result<ProofInitResult, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{

    let L = messages.len();
    let U = undisclosed_indexes.len();

    if random_scalars.len() != 5+U {
        return Err(Error::ProofGenError("Random scalars not valid".to_owned()))
    }

    if generators.message_generators.len() != L {
        return Err(Error::NotEnoughGenerators)
    }

    let domain = calculate_domain_new::<CS>(pk, &generators, header, api_id)?;

    let mut B = generators.g1_base_point + generators.q1 * domain;
    for i in 0..L {
        B = B + generators.message_generators[i] * messages[i].value;
    }

    let r1 = random_scalars[0];
    let r2 = random_scalars[1];
    let e_tilde = random_scalars[2];
    let r1_tilde = random_scalars[3];
    let r3_tilde = random_scalars[4];
    let m_tilde = &random_scalars[5..(5+U)];

    let D = B * r2;
    let Abar = signature.a * (r1 * r2);
    let Bbar = D * r1 - Abar * signature.e;


    let T1 = Abar * e_tilde + D * r1_tilde;
    let mut T2 = D * r3_tilde;

    for idx in 0..U {
        T2 = T2 + generators.message_generators[undisclosed_indexes[idx]] * m_tilde[idx];
    }

    Ok(ProofInitResult{ Abar, Bbar, D, T1, T2, domain })
}


fn proof_challenge_calculate<CS>(init_res: &ProofInitResult, disclosed_indexes: &[usize], disclosed_messages: &[BBSplusMessage], ph: Option<&[u8]>, api_id: Option<&[u8]>) -> Result<Scalar, Error>
where
    CS: BbsCiphersuite
{
    let R = disclosed_indexes.len();

    if disclosed_messages.len() != R {
        return Err(Error::ProofGenError("Number of disclosed indexes different from number of disclosed messages".to_owned()))
    }

    let api_id = api_id.unwrap_or(b"");
    let challenge_dst = [api_id, CS::H2S].concat();

    let ph = ph.unwrap_or(b"");

    let mut c_arr: Vec<u8> = Vec::new();
    c_arr.extend_from_slice(&init_res.Abar.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.Bbar.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.D.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.T1.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.T2.to_affine().to_compressed());
    c_arr.extend_from_slice(&i2osp(R, 8));
    disclosed_indexes.iter().for_each(|&i| c_arr.extend_from_slice(&i2osp(i, 8)));
    disclosed_messages.iter().for_each(|m| c_arr.extend_from_slice(&m.value.to_bytes_be()));
    c_arr.extend_from_slice(&init_res.domain.to_bytes_be());

    let ph_i2osp = i2osp(ph.len(), 8);

    c_arr.extend_from_slice(&ph_i2osp);
    c_arr.extend_from_slice(ph);

    let challenge = hash_to_scalar_new::<CS>(&c_arr, &challenge_dst)?;

    Ok(challenge)
}


fn proof_finalize(init_res: &ProofInitResult, challenge: Scalar, e: Scalar, random_scalars: &[Scalar], undisclosed_messages: &[BBSplusMessage]) -> Result<BBSplusPoKSignature, Error>
{

    let U = undisclosed_messages.len();

    let r1 = random_scalars[0];
    let r2 = random_scalars[1];
    let e_tilde = random_scalars[2];
    let r1_tilde = random_scalars[3];
    let r3_tilde = random_scalars[4];
    let m_tilde = &random_scalars[5..(5+U)];

    let r3 = Option::<Scalar>::from(r2.invert()).ok_or(Error::ProofGenError("Invert scalar failed".to_owned()))?;

    let e_cap = e_tilde + e  * challenge;

    let r1_cap = r1_tilde - r1 * challenge;
    let r3_cap = r3_tilde - r3 * challenge;
    let mut m_cap: Vec<Scalar> = Vec::new();

    for j in 0..U {
        let m_cap_j = m_tilde[j] + undisclosed_messages[j].value * challenge;
        m_cap.push(m_cap_j);
    }

    Ok(BBSplusPoKSignature{ Abar: init_res.Abar, Bbar: init_res.Bbar, D: init_res.D, e_cap, r1_cap, r3_cap, m_cap, challenge })
}


fn core_proof_verify<CS>(pk: &BBSplusPublicKey, proof: &BBSplusPoKSignature, generators: &Generators, header: Option<&[u8]>, ph: Option<&[u8]>, disclosed_messages: &[BBSplusMessage], disclosed_indexes: &[usize], api_id: Option<&[u8]>) -> Result<(), Error>
where
    CS: BbsCiphersuite
{
    let init_res = proof_verify_init::<CS>(
        pk, 
        proof, 
        generators, 
        header,
        disclosed_messages, 
        disclosed_indexes, 
        api_id
    )?;

    let challenge = proof_challenge_calculate::<CS>(&init_res, disclosed_indexes, disclosed_messages, ph, api_id)?;

    if proof.challenge != challenge {
        return Err(Error::PoKSVerificationError("invalid challenge".to_owned()));
    }

    let BP2 = G2Projective::GENERATOR;

    let term1 = (&proof.Abar.to_affine(), &G2Prepared::from(pk.0.to_affine()));
    let term2 = (&proof.Bbar.to_affine(), &G2Prepared::from(-BP2.to_affine()));

    let pairing = multi_miller_loop(&[term1, term2]).final_exponentiation();

    if pairing.is_identity().into() {
        Ok(())
    } else {
        Err(Error::PoKSVerificationError("Invalid Proof".to_owned()))
    }
}


fn proof_verify_init<CS>(pk: &BBSplusPublicKey, proof: &BBSplusPoKSignature, generators: &Generators, header: Option<&[u8]>, disclosed_messages: &[BBSplusMessage], disclosed_indexes: &[usize], api_id: Option<&[u8]>) -> Result<ProofInitResult, Error>
where
    CS: BbsCiphersuite
{
    let U = proof.m_cap.len();
    let R = disclosed_indexes.len();

    let L = U + R;

    for &i in disclosed_indexes {
        if i > L - 1 {
            return Err(Error::PoKSVerificationError("Invalid disclosed indexes".to_owned()))
        }
    }

    if disclosed_messages.len() != R {
        return Err(Error::PoKSVerificationError("len messages != len indexes".to_owned())) 
    }

    let undisclosed_indexes = get_remaining_indexes(L, disclosed_indexes);

    let domain = calculate_domain_new::<CS>(pk, generators, header, api_id)?;

    let T1 = proof.Bbar * proof.challenge + proof.Abar * proof.e_cap + proof.D * proof.r1_cap;
    let mut Bv = generators.g1_base_point + generators.q1 * domain;

    for i in 0..R {
        Bv += generators.message_generators[disclosed_indexes[i]] * disclosed_messages[i].value;
    }

    let mut T2 = Bv * proof.challenge + proof.D * proof.r3_cap;
    
    for j in 0..U {
        T2 += generators.message_generators[undisclosed_indexes[j]] * proof.m_cap[j];
    }

    Ok(ProofInitResult{ Abar: proof.Abar, Bbar: proof.Bbar, D: proof.D, T1, T2, domain })
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
        // let s_tilde = calculate_random_scalars::<CS>(1)[0];

        #[cfg(not(test))]
        let s_tilde = calculate_random_scalars(1)[0]; //TODO: to be fixed !!!!
    
        #[cfg(test)]
        let s_tilde = seeded_random_scalars::<CS>(1, None, None)[0];


		//  r~ = [U]
		//  for i in 1 to U: r~[i] = HASH(PRF(8 * ceil(log2(r)))) mod r
        // let r_tilde = calculate_random_scalars::<CS>(U);	

        #[cfg(not(test))]
        let r_tilde = calculate_random_scalars(U); //TODO: to be fixed !!!!
    
        #[cfg(test)]
        let r_tilde = seeded_random_scalars::<CS>(U, None, None);


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








#[cfg(test)]
mod test {
    use std::fs;

    use elliptic_curve::hash2curve::ExpandMsg;

    use crate::{bbsplus::{ciphersuites::BbsCiphersuite, keys::BBSplusPublicKey, proof::seeded_random_scalars}, schemes::{algorithms::{BBSplus, Scheme, BBS_BLS12381_SHA256, BBS_BLS12381_SHAKE256}, generics::{PoKSignature, Signature}}, utils::util::bbsplus_utils::{get_messages_vec, ScalarExt}};


    //mocked_rng - SHA256 - UPDATED
    #[test]
    fn mocked_rng_sha256() {
        mocked_rng::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "mockedRng.json");
    }

    //mocked_rng - SHAKE256 - UPDATED
    #[test]
    fn mocked_rng_shake256() {
        mocked_rng::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "mockedRng.json");
    }

    //SIGNATURE POK - SHA256
    #[test]
    fn proof_check_sha256_1() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature001.json", "proof/proof001.json")
    }
    #[test]
    fn proof_check_sha256_2() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof002.json")
    }
    #[test]
    fn proof_check_sha256_3() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof003.json")
    }
    #[test]
    fn proof_check_sha256_4() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof004.json")
    }
    #[test]
    fn proof_check_sha256_5() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof005.json")
    }
    #[test]
    fn proof_check_sha256_6() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof006.json")
    }
    #[test]
    fn proof_check_sha256_7() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof007.json")
    }
    #[test]
    fn proof_check_sha256_8() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof008.json")
    }
    #[test]
    fn proof_check_sha256_9() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof009.json")
    }
    #[test]
    fn proof_check_sha256_10() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof010.json")
    }
    #[test]
    fn proof_check_sha256_11() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof011.json")
    }
    #[test]
    fn proof_check_sha256_12() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof012.json")
    }
    #[test]
    fn proof_check_sha256_13() {
        proof_check::<BBS_BLS12381_SHA256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof013.json")
    }



    //SIGNATURE POK - SHAKE256

    #[test]
    fn proof_check_shake256_1() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature001.json", "proof/proof001.json")
    }
    #[test]
    fn proof_check_shake256_2() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof002.json")
    }
    #[test]
    fn proof_check_shake256_3() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof003.json")
    }
    #[test]
    fn proof_check_shake256_4() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof004.json")
    }
    #[test]
    fn proof_check_shake256_5() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof005.json")
    }
    #[test]
    fn proof_check_shake256_6() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof006.json")
    }
    #[test]
    fn proof_check_shake256_7() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof007.json")
    }
    #[test]
    fn proof_check_shake256_8() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof008.json")
    }
    #[test]
    fn proof_check_shake256_9() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof009.json")
    }
    #[test]
    fn proof_check_shake256_10() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof010.json")
    }
    #[test]
    fn proof_check_shake256_11() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof011.json")
    }
    #[test]
    fn proof_check_shake256_12() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof012.json")
    }
    #[test]
    fn proof_check_shake256_13() {
        proof_check::<BBS_BLS12381_SHAKE256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof013.json")
    }


    pub(crate) fn mocked_rng<S: Scheme>(pathname: &str, filename: &str) 
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
        let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        eprintln!("Mocked Random Scalars");

        let seed_ = hex::decode(res["seed"].as_str().unwrap()).unwrap();
        let dst = hex::decode(res["dst"].as_str().unwrap()).unwrap();
        let count: usize = res["count"].as_u64().unwrap().try_into().unwrap();

        let mocked_scalars_hex: Vec<&str> = res["mockedScalars"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();

        let r = seeded_random_scalars::<S::Ciphersuite>(count, Some(&seed_), Some(&dst));

        let mut results = true;

        for i in 0..count{
            let scalar_hex = hex::encode(r[i].to_bytes_be());

            let scalar_expected = mocked_scalars_hex[i];

            if scalar_hex != scalar_expected {
                if results == true {
                    results = false
                }
                eprintln!(" count: {}", i);
                eprintln!(" Expected scalar: {}", scalar_expected);
                eprintln!(" Computed scalar: {}", scalar_hex);
            }
        }


        assert!(results, "Failed");
    }
    
    pub(crate) fn proof_check<S: Scheme>(pathname: &str, sign_filename: &str, proof_filename: &str) 
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string([pathname, proof_filename].concat()).expect("Unable to read file");
        let proof_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");

        let signerPK_hex = proof_json["signerPublicKey"].as_str().unwrap();
        let header_hex = proof_json["header"].as_str().unwrap();
        let ph_hex = proof_json["presentationHeader"].as_str().unwrap();
        let input_messages: Vec<String> = proof_json["messages"].as_array().unwrap().iter().map(|m| serde_json::from_value(m.clone()).unwrap()).collect();

        let proof_expected = proof_json["proof"].as_str().unwrap();
        let result_expected = proof_json["result"]["valid"].as_bool().unwrap();

        let ph = hex::decode(ph_hex).unwrap();

        let revealed_message_indexes: Vec<usize> = proof_json["disclosedIndexes"].as_array().unwrap().iter().map(|m| serde_json::from_value(m.clone()).unwrap()).collect();

        //Get Message Signature
        let signature_expected = proof_json["signature"].as_str().unwrap();

        let signature = Signature::<BBSplus<S::Ciphersuite>>::from_bytes(hex::decode(signature_expected).unwrap().as_slice().try_into().unwrap());
        let bbs_signature = signature.bbsPlusSignature();
        
        let header = hex::decode(header_hex).unwrap();
        let PK = BBSplusPublicKey::from_bytes(&hex::decode(signerPK_hex).unwrap());

        let msgs: Vec<Vec<u8>> = input_messages.iter().map(|m| hex::decode(m).unwrap()).collect();

        let proof = PoKSignature::<BBSplus<S::Ciphersuite>>::proof_gen(bbs_signature, &PK, Some(&msgs), Some(&revealed_message_indexes), Some(&header), Some(&ph)).unwrap();  
        let my_encoded_proof =  hex::encode(&proof.to_bytes());
        let result0 = proof_expected == my_encoded_proof;
        let result1 = result0 == result_expected;
        if result1 == false{
            println!("  proofGen: {}", result1);
            println!("  Expected: {}", proof_expected);
            println!("  Computed: {}", my_encoded_proof);
            assert!(result1, "Failed");
        }


        // Verify the Proof 
        let disclosed_messages = get_messages_vec(&msgs, &revealed_message_indexes);

        let PROOF = PoKSignature::<BBSplus<S::Ciphersuite>>::from_bytes(&hex::decode(proof_expected).unwrap()).unwrap();

        
        let result2 = PROOF.proof_verify(&PK, Some(&disclosed_messages), Some(&revealed_message_indexes), Some(&header), Some(&ph)).is_ok();
        let result3 = result2 == result_expected;
        if !result3 {
            eprintln!("  proofVerify: {}", result3);
            eprintln!("  Expected: {}", result_expected);
            eprintln!("  Computed: {}", result2);
            assert!(result3, "failed");
        
        }else {
            eprintln!("  Expected: {}", signature_expected);
            eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));
        
            eprintln!("  proofVerify: {}", result3);
            eprintln!("  Expected: {}", result_expected);
            eprintln!("  Computed: {}", result2);
            if result_expected == false {
                eprintln!("{} ({})", result3, proof_json["result"]["reason"].as_str().unwrap());
            }
        }
    }
}
