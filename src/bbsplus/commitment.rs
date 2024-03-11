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

use std::os::windows::process;

use bls12_381_plus::{G1Affine, G1Projective, Scalar};
use serde::{Deserialize, Serialize};
use crate::{bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, errors::Error, schemes::{algorithms::BBSplus, generics::Commitment}, utils::{message::{BBSplusMessage, Message}, util::bbsplus_utils::{calculate_blind_challenge, subgroup_check_g1, ScalarExt}}};
use super::{keys::BBSplusPublicKey, proof::BBSplusZKPoK};
use elliptic_curve::hash2curve::{ExpandMsg, Expander};
use bls12_381_plus::group::Curve;

#[cfg(not(test))]
use crate::utils::util::bbsplus_utils::calculate_random_scalars;
#[cfg(test)]
use crate::utils::util::bbsplus_utils::seeded_random_scalars;


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusCommitment {
    pub commitment: G1Projective,
    pub proof: BBSplusZKPoK
}

impl BBSplusCommitment {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.commitment.to_affine().to_compressed());
        bytes.extend_from_slice(&self.proof.to_bytes());
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
    
        let commitment = parse_g1_affine(&bytes[0..48])?;
        let proof = BBSplusZKPoK::from_bytes(&bytes[48..])?;

        Ok(Self { commitment, proof })

    }
}


impl <CS: BbsCiphersuite> Commitment<BBSplus<CS>> {

    pub fn commit(committed_messages: Option<&[Vec<u8>]>) -> Result<(Self, SecretProverBlind), Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let (commitment_with_proof, secret) = commit::<CS>(committed_messages, Some(CS::API_ID_BLIND))?;
        Ok((Self::BBSplus(commitment_with_proof), secret))

    }



    pub fn validate(&self) -> Result<(), Error>{

        let (commitment, proof) = match self {
            Commitment::BBSplus(inner) => (inner.commitment, &inner.proof),
            _ => return Err(Error::UnespectedError),
        };

        let M = proof.m_cap.len();

        let blind_generators = Generators::create::<CS>(M+2, Some(CS::API_ID_BLIND)).message_generators;

        verify_commitment::<CS>(commitment, proof, &blind_generators, Some(CS::API_ID_BLIND))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Commitment::BBSplus(inner) => inner.to_bytes(),
            _ => panic!("{}", Error::UnespectedError),
        }

    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusCommitment::from_bytes(bytes)?))  
    }

}


pub struct SecretProverBlind(Scalar);

impl SecretProverBlind {
    pub fn to_bytes(&self) -> [u8; 32]{
        self.0.to_be_bytes()
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self(Scalar::from_bytes_be(bytes)?))
    }
}


/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-generators-calculation -> generators = create_generators(count, api_id)
/// 
/// # Description
/// This operation is used by the Prover to create a commitment to a set of messages (committed_messages), that they intend to include to the blind signature. Note that this operation returns both the serialized combination of the commitment and its proof of correctness (commitment_with_proof), as well as the random scalar used to blind the commitment (secret_prover_blind).
/// 
/// # Inputs:
/// * `committed_messages` (OPTIONAL), a vector of octet strings. If not
/// supplied it defaults to the empty
/// array ("()").
/// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string ("").
/// 
/// # Output:
/// ([`BBSplusCommitment`], [`SecretProverBlind`]), a tuple comprising from a commitmentment + proof and a random scalar in tha order.
/// 
fn commit<CS>(committed_messages: Option<&[Vec<u8>]>, api_id: Option<&[u8]>) -> Result<(BBSplusCommitment, SecretProverBlind), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let committed_messages = committed_messages.unwrap_or(&[]);
    let M = committed_messages.len();
    let api_id = api_id.unwrap_or(b"");

    let commited_message_scalars = BBSplusMessage::messages_to_scalar::<CS>(committed_messages, api_id)?;

    let generators = Generators::create::<CS>(M+2, Some(api_id)).message_generators;

    let Q2 = generators[0];
    let Js = &generators[1..];

    #[cfg(not(test))]
    let random_scalars = calculate_random_scalars(M + 2);

    #[cfg(test)]
    let random_scalars = seeded_random_scalars::<CS>(M + 2, Some(b"3.141592653589793238462643383279"), Some(CS::COMMIT_DST));

    let secret_prover_blind = random_scalars[0];
    let s_tilde = random_scalars[1];
    let m_tilde = &random_scalars[2..(M+2)];

    let mut commitment = Q2 * secret_prover_blind;

    for i in 0..M {
        commitment += Js[i] * commited_message_scalars[i].value;
    }

    let mut Cbar = Q2 * s_tilde;
    for i in 0..M {
        Cbar += Js[i] * m_tilde[i];
    }

    let mut gens = Vec::new();
    gens.push(Q2);
    gens.extend_from_slice(Js);

    let challenge = calculate_blind_challenge::<CS>(commitment, Cbar, &gens, Some(api_id))?;
    let s_cap = s_tilde + secret_prover_blind * challenge;

    let mut m_cap = Vec::new();
    for m in 0..M {
        let v = m_tilde[m] + commited_message_scalars[m].value * challenge;
        m_cap.push(v);
    }

    let proof = BBSplusZKPoK::new(s_cap, m_cap, challenge);
    let commitment_with_proof = BBSplusCommitment{ commitment, proof};
    let secret = SecretProverBlind(secret_prover_blind);


    Ok((commitment_with_proof, secret))
}


fn verify_commitment<CS>(commitment: G1Projective, commitment_proof: &BBSplusZKPoK, blind_generators: &[G1Projective], api_id: Option<&[u8]>) -> Result<(), Error> 
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let api_id = api_id.unwrap_or(b"");
    let M = commitment_proof.m_cap.len();

    if blind_generators.len() != M + 1 {
        return Err(Error::NotEnoughGenerators)
    }

    let G2 = blind_generators[0];
    let Js = &blind_generators[1..];
    let mut Cbar = G2 * commitment_proof.s_cap;
    for i in 0..M {
        Cbar += Js[i] * commitment_proof.m_cap[i];
    }

    Cbar += commitment * (-commitment_proof.challenge);

    let cv = calculate_blind_challenge::<CS>(commitment, Cbar, blind_generators, Some(api_id))?;

    if cv != commitment_proof.challenge {
        Err(Error::InvalidCommitmentProof)
    } else {
        Ok(())
    }

}


#[cfg(test)]
mod tests {
    use std::fs;

    use elliptic_curve::hash2curve::ExpandMsg;

    use crate::{bbsplus::ciphersuites::BbsCiphersuite, schemes::{algorithms::{BBSplus, Scheme, BBS_BLS12381_SHA256, BBS_BLS12381_SHAKE256}, generics::Commitment}};


    // Commitment - SHA256
    
    #[test]
    fn commit_sha256_1() {
        commit::<BBS_BLS12381_SHA256>("./fixture_data_blind/bls12-381-sha-256/", "commit/commit001.json");
    }

    #[test]
    fn commit_sha256_2() {
        commit::<BBS_BLS12381_SHA256>("./fixture_data_blind/bls12-381-sha-256/", "commit/commit002.json");
    }

    // Commitment - SHAKE256
    
    #[test]
    fn commit_shake256_1() {
        commit::<BBS_BLS12381_SHAKE256>("./fixture_data_blind/bls12-381-shake-256/", "commit/commit001.json");
    }

    #[test]
    fn commit_shake256_2() {
        commit::<BBS_BLS12381_SHAKE256>("./fixture_data_blind/bls12-381-shake-256/", "commit/commit002.json");
    }


    fn commit<S: Scheme>(pathname: &str, filename: &str) 
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
        let proof_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        println!("{}", proof_json["caseName"]);

        // let seed = proof_json["mockRngParameters"]["SEED"].as_str().unwrap().as_bytes();
        // let dst = proof_json["mockRngParameters"]["commit"]["DST"].as_str().unwrap().as_bytes();
        // let count: usize = proof_json["mockRngParameters"]["commit"]["count"].as_u64().unwrap().try_into().unwrap();

        
        let committed_messages: Vec<String>= proof_json["committedMessages"].as_array().unwrap().iter().map(|m| serde_json::from_value(m.clone()).unwrap()).collect();
        let prover_blind = proof_json["proverBlind"].as_str().unwrap();
        let commitment_with_proof = proof_json["commitmentWithProof"].as_str().unwrap();

        println!("blind: {}", prover_blind);

        let committed_messages: Vec<Vec<u8>> = committed_messages.iter().map(|m| hex::decode(m).unwrap()).collect();

        let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

        let (commitment_with_proof_result, secret) = Commitment::<BBSplus<S::Ciphersuite>>::commit(Some(&committed_messages)).unwrap();

        assert_eq!(hex::encode(commitment_with_proof_result.to_bytes()), commitment_with_proof);

        assert_eq!(hex::encode(secret.to_bytes()), prover_blind);

        let result = commitment_with_proof_result.validate().is_ok();

        assert_eq!(result, expected_result);
        
    }
}