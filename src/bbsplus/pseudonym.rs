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

use bls12_381_plus::Scalar;
use elliptic_curve::hash2curve::ExpandMsg;
use crate::errors::Error;
use crate::schemes::algorithms::BBSplus;
use crate::bbsplus::commitment::BBSplusCommitment; // Import the missing type
use crate::schemes::generics::Commitment;
use crate::utils::message::bbsplus_message::BBSplusMessage;
use crate::utils::util::bbsplus_utils::{get_random, ScalarExt};

use super::ciphersuites::BbsCiphersuite;
use super::commitment::{core_commit, BlindFactor};
use super::generators::Generators;

//#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
///
#[derive(Debug)]
/// A struct representing a pseudonym secret factor used in BBS+ pseudonyms.
pub struct PseudonymSecret(pub(crate) Scalar);

impl PseudonymSecret {
    /// Generates a random PseudonymSecret.
    pub fn random() -> Self {
        Self(get_random())
    }

    /// Converts the PseudonymSecret to a byte array.
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

impl Into<BBSplusMessage> for &PseudonymSecret {
    fn into(self) -> BBSplusMessage {
        BBSplusMessage::new(self.0)
    }
}


impl<CS: BbsCiphersuite> Commitment<BBSplus<CS>>{
    /// # Description
    /// This operation is used by the Prover to create a commitment to a set of messages (committed_messages),
    /// that they intend to include to the blind signature. Note that this operation returns both
    /// the serialized combination of the commitment and its proof of correctness (commitment_with_proof),
    /// as well as the random scalar used to blind the commitment (secret_prover_blind). 
    /// They will also choose their part of the pseudonym secret prover_nym as a random scalar value
    ///
    /// # Inputs:
    /// * `committed_messages` (OPTIONAL), a vector of octet strings. If not supplied it defaults to the empty array.
    /// * `prover_nym ` (OPTIONAL), a random `[PseudonymSecret]`. If not supplied, it defaults to the zero value (0).
    ///
    /// # Output:
    /// ([`Commitment::BBSplus`], [`BlindFactor`]), a tuple (**`commitment_with_proof`**, **`secret_prover_blind`**) or [`Error`].
    ///
    pub fn commit_with_nym(committed_messages: Option<&[Vec<u8>]>, prover_nym: Option<&PseudonymSecret>) -> Result<(Self, BlindFactor), Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let (commitment_with_proof, secret) =
            commit_with_nym::<CS>(committed_messages, prover_nym, Some(CS::API_ID_NYM))?;
        Ok((Self::BBSplus(commitment_with_proof), secret))
    }
        
}


/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-01#name-commitment
///
/// # Description
/// The Prover will chose a set of messages committed_messages that they want to be included in the signature,
/// without reveling them to the Signer. They will also choose their part of the pseudonym secret prover_nym as a random scalar value
/// 
/// # Inputs:
/// * `committed_messages` (OPTIONAL), a vector of octet strings. If not supplied it defaults to the empty array.
/// * `prover_nym ` (OPTIONAL), a random `[PseudonymSecret]`. If not supplied, it defaults to the zero scalar (0).
/// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string.
///
/// # Output:
/// ([`BBSplusCommitment`], [`BlindFactor`]), a tuple (commitment + proof, secret_prover_blind) or [`Error`].
///
fn commit_with_nym<CS>(
    committed_messages: Option<&[Vec<u8>]>,
    prover_nym: Option<&PseudonymSecret>,
    api_id: Option<&[u8]>,
) -> Result<(BBSplusCommitment, BlindFactor), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let committed_messages = committed_messages.unwrap_or(&[]);
    let prover_nym = prover_nym.unwrap_or(&PseudonymSecret(Scalar::ZERO));
    let api_id = api_id.unwrap_or(b"");

    println!("Prover Nym: {}", hex::encode(prover_nym.to_bytes()));

    let mut commited_message_scalars =
        BBSplusMessage::messages_to_scalar::<CS>(committed_messages, api_id)?;

    commited_message_scalars.push(prover_nym.into());
    
    let blind_generators = Generators::create::<CS>(
        commited_message_scalars.len() + 1, 
        Some(&[b"BLIND_", api_id].concat())
    ).values;

    core_commit::<CS>(blind_generators,Some(commited_message_scalars), Some(api_id))

}


#[cfg(test)]
mod tests {
    use std::fs;

    use elliptic_curve::hash2curve::ExpandMsg;

    use crate::{
        bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators, pseudonym::PseudonymSecret},
        schemes::{
            algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
            generics::Commitment,
        },
    };

    // Commitment

    macro_rules! commit_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { commit_with_nym::<$t>($p, $f); }
        )+)+ }
    }

    commit_tests! {
        (BbsBls12381Sha256, "./fixture_data_nym/bls12-381-sha-256/"): {
            (commit_sha256_1, "nymCommit/nym_commit001.json"),
        },
        (BbsBls12381Shake256, "./fixture_data_nym/bls12-381-shake-256/"): {
            (commit_shake256_1, "nymCommit/nym_commit001.json"),
        },
    }

    fn commit_with_nym<S: Scheme>(pathname: &str, filename: &str)
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
        let prover_nym = proof_json["proverNym"].as_str().unwrap();

        let prover_nym_vec = hex::decode(prover_nym).unwrap();
        let prover_nym_array: [u8; 32] = prover_nym_vec.try_into().expect("Invalid length");
        let prover_nym = PseudonymSecret::from_bytes(&prover_nym_array).unwrap();

        let committed_messages: Vec<Vec<u8>> = committed_messages
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect();

        let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

        let (commitment_with_proof_result, secret) =
        Commitment::<BBSplus<S::Ciphersuite>>::commit_with_nym(Some(&committed_messages), Some(&prover_nym)).unwrap();

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






