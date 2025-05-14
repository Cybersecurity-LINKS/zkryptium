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

use super::proof::BBSplusZKPoK;
use crate::{
    bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators},
    errors::Error,
    schemes::{algorithms::BBSplus, generics::Commitment},
    utils::{
        message::bbsplus_message::BBSplusMessage,
        util::bbsplus_utils::{
            calculate_blind_challenge, get_random, parse_g1_projective, ScalarExt,
        },
    },
};
use bls12_381_plus::group::Curve;
use bls12_381_plus::{G1Projective, Scalar};
use elliptic_curve::hash2curve::ExpandMsg;
use serde::{Deserialize, Serialize};

#[cfg(not(test))]
use crate::utils::util::bbsplus_utils::calculate_random_scalars;
#[cfg(test)]
use crate::utils::util::bbsplus_utils::seeded_random_scalars;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// A struct representing a BBS+ commitment, which includes the commitment itself and a proof of knowledge.
pub struct BBSplusCommitment {
    /// The commitment itself.
    pub commitment: G1Projective,
    /// The proof of knowledge.
    pub proof: BBSplusZKPoK,
}

impl BBSplusCommitment {
    /// Converts the BBSplusCommitment to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.commitment.to_affine().to_compressed());
        bytes.extend_from_slice(&self.proof.to_bytes());
        bytes
    }

    /// Converts a byte slice to a BBSplusCommitment.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the serialized BBSplusCommitment.
    ///
    /// # Returns
    ///
    /// * A result containing the `BBSplusCommitment` or an error.
    /// Converts a byte slice to a Commitment.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the serialized Commitment.
    ///
    /// # Returns
    ///
    /// * A result containing the `Commitment` or an error.
    /// Converts a byte slice to a Commitment.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the serialized Commitment.
    ///
    /// # Returns
    ///
    /// * A result containing the `Commitment` or an error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let commitment = parse_g1_projective(&bytes[0..G1Projective::COMPRESSED_BYTES])
            .map_err(|_| Error::InvalidCommitment)?;
        let proof = BBSplusZKPoK::from_bytes(&bytes[G1Projective::COMPRESSED_BYTES..])
            .map_err(|_| Error::InvalidCommitmentProof)?;

        Ok(Self { commitment, proof })
    }
}

impl<CS: BbsCiphersuite> Commitment<BBSplus<CS>> {
    /// # Description
    /// This operation is used by the Prover to create a commitment to a set of messages (committed_messages),
    /// that they intend to include to the blind signature. Note that this operation returns both
    /// the serialized combination of the commitment and its proof of correctness (commitment_with_proof),
    /// as well as the random scalar used to blind the commitment (secret_prover_blind).
    ///
    /// # Inputs:
    /// * `committed_messages` (OPTIONAL), a vector of octet strings. If not supplied it defaults to the empty array.
    ///
    /// # Output:
    /// ([`Commitment::BBSplus`], [`BlindFactor`]), a tuple (**`commitment_with_proof`**, **`secret_prover_blind`**) or [`Error`].
    ///
    pub fn commit(committed_messages: Option<&[Vec<u8>]>) -> Result<(Self, BlindFactor), Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let (commitment_with_proof, secret) =
            commit::<CS>(committed_messages, Some(CS::API_ID_BLIND))?;
        Ok((Self::BBSplus(commitment_with_proof), secret))
    }

    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-01#name-commitment-validation-and-d>
    ///
    /// # Description
    /// The following is a helper operation used by the BlindSign procedure to validate an optional commitment.
    /// If a commitment is not supplied, or if it is the Identity_G1, the following operation will return the Identity_G1
    /// as the "default" commitment point, which will be ignored by all computations during BlindSign.
    ///
    /// # Inputs:
    /// * `commitment_with_proof` (OPTIONAL), octet string representing the serialization of [`BBSplusCommitment`]. 
    ///                                       If it is not supplied it defaults to the empty octet string.
    /// * `blind_generators` (OPTIONAL), vector of points of G1. If it is not supplied it defaults to the empty set
    /// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string ("").
    ///
    /// # Output:
    /// * [`G1Projective`], a commitment; or [`Error`].
    ///
    pub fn deserialize_and_validate_commit(
        commitment_with_proof: Option<&[u8]>,
        blind_generators: &Generators,
        api_id: Option<&[u8]>,
    ) -> Result<G1Projective, Error> {
        let commitment_with_proof: &[u8] = commitment_with_proof.unwrap_or(&[]);
        if commitment_with_proof.is_empty() {
            return Ok(G1Projective::IDENTITY);
        }

        let api_id = api_id.unwrap_or(b"");

        let commitment_with_proof: Commitment<BBSplus<CS>> = Self::from_bytes(commitment_with_proof)?;

        let (commitment, proof) = match commitment_with_proof {
            Commitment::BBSplus(inner) => (inner.commitment, inner.proof),
            _ => return Err(Error::UnespectedError),
        };

        let M = proof.m_cap.len() + 1;
        if blind_generators.values.len() < M {
            return Err(Error::NotEnoughGenerators);
        }

        if core_commit_verify::<CS>(
            commitment,
            &proof,
            &blind_generators.values,
            Some(api_id)
        ).is_ok() {
            Ok(commitment)
        } else {
            Err(Error::InvalidCommitmentProof)
        }
    }

    /// Converts the Commitment to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Commitment::BBSplus(inner) => inner.to_bytes(),
            _ => panic!("{}", Error::UnespectedError),
        }
    }
    
    /// Converts a byte slice to a Commitment
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte array representing the serialized Commitment.
    ///
    /// # Returns
    ///
    /// * A result containing the `Commitment` or an error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusCommitment::from_bytes(bytes)?))
    }
}

#[derive(Debug)]
/// A struct representing a blind factor used in BBS+ commitments.
pub struct BlindFactor(pub(crate) Scalar);

impl BlindFactor {
    /// Generates a random blind factor.
    pub fn random() -> Self {
        Self(get_random())
    }

    /// Converts the BlindFactor to a byte array.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_be_bytes()
    }

    /// Converts a byte array to a BlindFactor.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte array representing the serialized BlindFactor.
    ///
    /// # Returns
    ///
    /// * A result containing the `BlindFactor` or an error.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self(Scalar::from_bytes_be(bytes)?))
    }
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-01#name-commitment-operations
///
/// # Description
/// This operation is used by the Prover to create a commitment to a set of messages (committed_messages),
/// that they intend to include to the blind signature. Note that this operation returns both
/// the serialized combination of the commitment and its proof of correctness (commitment_with_proof),
/// as well as the random scalar used to blind the commitment (secret_prover_blind).
///
/// # Inputs:
/// * `committed_messages` (OPTIONAL), a vector of octet strings. If not supplied it defaults to the empty array.
/// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string.
///
/// # Output:
/// ([`BBSplusCommitment`], [`BlindFactor`]), a tuple (commitment + proof, secret_prover_blind) or [`Error`].
///
fn commit<CS>(
    committed_messages: Option<&[Vec<u8>]>,
    api_id: Option<&[u8]>,
) -> Result<(BBSplusCommitment, BlindFactor), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let committed_messages: &[Vec<u8>] = committed_messages.unwrap_or(&[]);
    let api_id = api_id.unwrap_or(b"");

    let commited_message_scalars: Vec<BBSplusMessage> =
        BBSplusMessage::messages_to_scalar::<CS>(committed_messages, api_id)?;
    
    let blind_generators: Vec<G1Projective> = Generators::create::<CS>(
        commited_message_scalars.len() + 1, 
        Some(&[b"BLIND_", api_id].concat())
    ).values;

    core_commit::<CS>(blind_generators,Some(commited_message_scalars), Some(api_id))

}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-01#name-core-commitment-computation
/// 
/// # Description
/// 
/// This operation is used by the Prover to create a commitment to a set of messages (committed_messages), 
/// that they intend to include to the blind signature. Note that this operation returns both 
/// the serialized combination of the commitment and its proof of correctness (commitment_with_proof), 
/// as well as the random scalar used to blind the commitment (secret_prover_blind).
/// 
/// # Inputs:
/// * `blind_generators`  (REQUIRED), vector of pseudo-random points in G1.
/// * `committed_messages_scalars ` (OPTIONAL), a vector of scalars. If not supplied, it defaults to the empty array ("()").
/// * `api_id`  (OPTIONAL), an octet string. If not supplied it defaults to the empty octet string ("").
///
/// # Output:
/// ([`BBSplusCommitment`], [`BlindFactor`]), a tuple (commit_with_proof + proof, secret_prover_blind) or [`Error`].
///
pub(super) fn core_commit<CS>(
    blind_generators: Vec<G1Projective>,
    committed_messages_scalars: Option<Vec<BBSplusMessage>>,
    api_id: Option<&[u8]>,
) -> Result<(BBSplusCommitment, BlindFactor), Error> 
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
    {

    let committed_messages_scalars: Vec<BBSplusMessage> = committed_messages_scalars.unwrap_or(Vec::new());
    let api_id: &[u8] = api_id.unwrap_or(b"");

    let M: usize = committed_messages_scalars.len();
    
    if blind_generators.len() != M + 1  {
        return Err(Error::InvalidNumberOfGenerators);
    }

    let blind_gens = blind_generators.clone();
    
    let Q2: G1Projective = blind_generators[0];
    let Js: &[G1Projective] = &blind_generators[1..M + 1];

    #[cfg(not(test))]
    let random_scalars = calculate_random_scalars(M + 2);

    #[cfg(test)]
    let random_scalars: Vec<Scalar> = seeded_random_scalars::<CS>(M + 2, CS::SEED_MOCKED_SCALAR, CS::COMMIT_DST);

    let secret_prover_blind: Scalar = random_scalars[0];
    let s_tilde: Scalar = random_scalars[1];
    let m_tilde: &[Scalar] = &random_scalars[2..(M + 2)];

    let mut commitment: G1Projective = Q2 * secret_prover_blind;
    
    for i in 0..M {
        commitment += Js[i] * committed_messages_scalars[i].value;
    }

    let mut Cbar = Q2 * s_tilde;
    for i in 0..M {
        Cbar += Js[i] * m_tilde[i];
    }

    let challenge = calculate_blind_challenge::<CS>(
        commitment, 
        Cbar,
        &blind_gens,
        Some(api_id)
    )?;

    let s_cap: Scalar = s_tilde + secret_prover_blind * challenge;

    let mut m_cap = Vec::new();

    for m in 0..M {
        let v: Scalar = m_tilde[m] + committed_messages_scalars[m].value * challenge;
        m_cap.push(v);
    }

    let proof: BBSplusZKPoK = BBSplusZKPoK::new(s_cap, m_cap, challenge);
    let commitment_with_proof: BBSplusCommitment = BBSplusCommitment { commitment, proof };
    let secret_prover_blind: BlindFactor = BlindFactor(secret_prover_blind);

    Ok((commitment_with_proof, secret_prover_blind))
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-01#name-core-commitment-verificatio
///
/// # Description
/// This operation is used by the Signer to verify the correctness of a commitment_proof for a supplied commitment,
/// over a list of points of G1 called the blind_generators, used to compute that commitment.
///
/// # Inputs:
/// * `commitment` (REQUIRED), a commitment.
/// * `commitment_proof` (REQUIRED), a commitment_proof [`BBSplusZKPoK`].
/// * `blind_generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string.
///
/// # Output:
/// a result [`Ok`] or [`Error`].
///
 fn core_commit_verify<CS>(
    commitment: G1Projective,
    commitment_proof: &BBSplusZKPoK,
    blind_generators: &[G1Projective],
    api_id: Option<&[u8]>,
) -> Result<(), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let api_id = api_id.unwrap_or(b"");
    let M = commitment_proof.m_cap.len();

    let blind_generators = blind_generators
        .get(..M + 1)
        .ok_or(Error::InvalidNumberOfGenerators)?;

    let G2: G1Projective = blind_generators[0];
    let Js: &[G1Projective] = &blind_generators[1..];
    let mut Cbar: G1Projective = G2 * commitment_proof.s_cap;
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

    use crate::{
        bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators},
        schemes::{
            algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
            generics::Commitment,
        },
    };

    // Commitment

    macro_rules! commit_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { commit::<$t>($p, $f); }
        )+)+ }
    }

    commit_tests! {
        (BbsBls12381Sha256, "./fixture_data/fixture_data_blind/bls12-381-sha-256/"): {
            (commit_sha256_1, "commit/commit001.json"),
            (commit_sha256_2, "commit/commit002.json"),
        },
        (BbsBls12381Shake256, "./fixture_data/fixture_data_blind/bls12-381-shake-256/"): {
            (commit_shake256_1, "commit/commit001.json"),
            (commit_shake256_2, "commit/commit002.json"),
        },
    }

    fn commit<S: Scheme>(pathname: &str, filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
        let proof_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        println!("{}", proof_json["caseName"]);

        let committed_messages: Vec<String> = proof_json["committedMessages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| serde_json::from_value(m.clone()).unwrap())
            .collect();
        let prover_blind = proof_json["proverBlind"].as_str().unwrap();
        let commitment_with_proof = proof_json["commitmentWithProof"].as_str().unwrap();

        let committed_messages: Vec<Vec<u8>> = committed_messages
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect();

        let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

        let (commitment_with_proof_result, secret) =
            Commitment::<BBSplus<S::Ciphersuite>>::commit(Some(&committed_messages)).unwrap();

        let commitment_with_proof_result_oct = commitment_with_proof_result.to_bytes();
        assert_eq!(
            hex::encode(&commitment_with_proof_result_oct),
            commitment_with_proof
        );

        assert_eq!(hex::encode(secret.to_bytes()), prover_blind);

        let blind_generators = Generators::create::<S::Ciphersuite>(
            committed_messages.len() + 1,
            Some(&[b"BLIND_", <S::Ciphersuite as BbsCiphersuite>::API_ID_BLIND].concat()),
        );

        let result = Commitment::<BBSplus<S::Ciphersuite>>::deserialize_and_validate_commit(
            Some(&commitment_with_proof_result_oct),
            &blind_generators,
            Some(<S::Ciphersuite as BbsCiphersuite>::API_ID_BLIND),
        )
        .is_ok();

        assert_eq!(result, expected_result);
    }
}
