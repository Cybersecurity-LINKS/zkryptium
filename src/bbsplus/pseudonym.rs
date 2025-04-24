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

use bls12_381_plus::{G1Projective, Scalar};
use elliptic_curve::hash2curve::ExpandMsg;
use crate::errors::Error;
use crate::schemes::algorithms::BBSplus;
use crate::bbsplus::commitment::BBSplusCommitment; // Import the missing type
use crate::schemes::generics::{BlindSignature, Commitment};
use crate::utils::message::bbsplus_message::BBSplusMessage;
use crate::utils::util::bbsplus_utils::{get_random, ScalarExt};

use super::blind::finalize_blind_sign;
use super::ciphersuites::BbsCiphersuite;
use super::commitment::{core_commit, BlindFactor};
use super::generators::Generators;
use super::keys::{BBSplusPublicKey, BBSplusSecretKey};

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

    /// Converts a byte array to a PseudonymSecret.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte array representing the serialized PseudonymSecret.
    ///
    /// # Returns
    ///
    /// * A result containing the `PseudonymSecret` or an error.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        Ok(Self(Scalar::from_bytes_be(bytes)?))
    }

    /// Converts an hex sring byte array to a PseudonymSecret.
    ///
    /// # Arguments
    ///
    /// * `hex` - An hex stre representing the serialized PseudonymSecret.
    ///
    /// # Returns
    ///
    /// * A result containing the `PseudonymSecret` or an error.
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        let scalar = Scalar::from_be_hex(hex).into_option().ok_or(Error::InvalidPseudonym)?;
        Ok(Self(scalar))
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

    let mut commited_message_scalars =
        BBSplusMessage::messages_to_scalar::<CS>(committed_messages, api_id)?;

    commited_message_scalars.push(prover_nym.into());
    
    let blind_generators = Generators::create::<CS>(
        commited_message_scalars.len() + 1, 
        Some(&[b"BLIND_", api_id].concat())
    ).values;

    core_commit::<CS>(blind_generators,Some(commited_message_scalars), Some(api_id))

}

impl<CS: BbsCiphersuite> BlindSignature<BBSplus<CS>> {
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-01#name-blind-issuance>
    ///
    /// # Description
    /// The Signer generate a signature from a secret key (SK), the commitment with proof,
    /// the signer_nym_entropy and optionally over a header and vector of messages using
    /// the BlindSignWithNym procedure shown below. Typically the signer_nym_entropy will
    /// be a fresh random scalar, however in the case of "reissue" of a signature for
    /// a prover who wants to keep their same pseudonymous identity this value
    /// can be reused for the same prover if desired.
    ///
    /// # Inputs:
    /// * `sk` (REQUIRED), a secret key
    /// * `pk` (REQUIRED), a public key
    /// * `commitment_with_proof` (OPTIONAL), an octet string, representing a serialized commitment and commitment_proof,
    ///                                       as the first element outputted by the `commit_with_nym` operation. 
    ///                                       If not supplied, it defaults to the empty string ("").
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    /// * `signer_nym_entropy` (REQUIRED), a [`PseudonymSecret`] value
    /// * `messages` (OPTIONAL), a vector of octet strings. If not supplied, it defaults to the empty array.
    ///
    /// # Output:
    /// a [`BlindSignature::BBSplus`] or [`Error`].
    ///
    pub fn blind_sign_with_nym(
        sk: &BBSplusSecretKey,
        pk: &BBSplusPublicKey,
        commitment_with_proof: Option<&[u8]>,
        header: Option<&[u8]>,
        signer_nym_entropy: &PseudonymSecret,
        messages: Option<&[Vec<u8>]>,
    ) -> Result<Self, Error> {
        let messages = messages.unwrap_or(&[]);
        let L = messages.len();
        let commitment_with_proof = commitment_with_proof.unwrap_or(&[]);

        let mut M: usize = commitment_with_proof.len();

        //commitment_with_proof = g1_point + [s_hat, m_hat0...m_hatM, challenge]
        //M = (length(commitment_with_proof) - point_length - 2*scalar_length)/scalar_length
        if M != 0 {
            M = M
                .checked_sub(G1Projective::COMPRESSED_BYTES)
                .ok_or(Error::InvalidCommitmentProof)?;
            M = M
                .checked_sub(2 * Scalar::BYTES)
                .ok_or(Error::InvalidCommitmentProof)?;
            M = M
                .checked_div(Scalar::BYTES)
                .ok_or(Error::InvalidCommitmentProof)?;
        }
   
        let generators = Generators::create::<CS>(L + 1, Some(CS::API_ID_NYM));

        //M+1 Taken from grotto bbs lib
        let blind_generators =
            Generators::create::<CS>(M + 1, Some(&[b"BLIND_", CS::API_ID_NYM].concat()));

        let commit: G1Projective = Commitment::<BBSplus<CS>>::deserialize_and_validate_commit(
            Some(commitment_with_proof),
            &blind_generators,
            Some(CS::API_ID_NYM)
        )?;
        
        let message_scalars: Vec<BBSplusMessage> = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID_NYM)?;

        let nym_generator = blind_generators.last().expect("Blind nym generator not found");

        let mut B: Vec<G1Projective> = b_calculate_with_nym(
            &signer_nym_entropy,
            &generators, 
            Some(commit),
            nym_generator,
            message_scalars
        )?;

        let B_val = B.pop().unwrap();

        let blind_sig = finalize_blind_sign::<CS>(
            sk,
            pk,
            B_val,
            &generators,
            &blind_generators,
            header,
            Some(CS::API_ID_NYM),
        )?;

        Ok(Self::BBSplus(blind_sig))
    }

}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-01#name-calculate-b
///
/// # Description
/// The b_calculate_with_nym is defined to return an array of elements, to establish extendability of the scheme 
/// by allowing the B_calculate operation to return more elements than just the point to be signed.
///
/// # Inputs:
/// * `signer_nym_entropy` (REQUIRED), a [`PseudonymSecret`] value
/// * `generators` (REQUIRED), an array of at least one point from the G1 group
/// * `commitment` (OPTIONAL), a point from the G1 group. If not supplied it defaults to the Identity_G1 point.
/// * `nym_generator` (REQUIRED), a point from the G1 group
/// * `message_scalars` (OPTIONAL), an array of scalar values. If not supplied, it defaults to the empty array ("()")
/// 
/// # Output:
/// a [`Vec<G1Projective>`] an array of a single element from the G1 subgroup or [`Error`].
///
fn b_calculate_with_nym(
    signer_nym_entropy: &PseudonymSecret,
    generators: &Generators,
    commitment: Option<G1Projective>,
    nym_generator: &G1Projective,
    message_scalars: Vec<BBSplusMessage>,
) -> Result<Vec<G1Projective>, Error> {

    let commitment = commitment.unwrap_or(G1Projective::IDENTITY);

    let L = message_scalars.len();
    
    if generators.values.len() != L + 1 {
        return Err(Error::InvalidNumberOfGenerators);
    }
    
    let _Q1 = generators.values[0];
    let H_points = &generators.values[1..];

    //let mut B = Q1;
    let mut B = generators.g1_base_point; //TODO: Edit taken from Grotto bbs sig library

    for i in 0..L {
        B += H_points[i] * message_scalars[i].value;
    }
    
    B += commitment;

    B += nym_generator * signer_nym_entropy.0;

    if B.is_identity().into() {
        return Err(Error::G1IdentityError);
    }

    let mut b_value:Vec<G1Projective> = Vec::<G1Projective>::new();
    b_value.push(B);

    Ok(b_value)

}

#[cfg(test)]
mod tests {
    use std::fs;

    use elliptic_curve::hash2curve::ExpandMsg;

    use crate::{
        bbsplus::{ciphersuites::BbsCiphersuite, commitment::BlindFactor, generators::Generators, keys::{BBSplusPublicKey, BBSplusSecretKey}, pseudonym::PseudonymSecret},
        schemes::{
            algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
            generics::{BlindSignature, Commitment},
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
            (commit_sha256_1, "nymCommit/nymCommit001.json"),
            (commit_sha256_2, "nymCommit/nymCommit002.json"),
        },
        (BbsBls12381Shake256, "./fixture_data_nym/bls12-381-shake-256/"): {
            (commit_shake256_1, "nymCommit/nymCommit001.json"),
            (commit_shake256_2, "nymCommit/nymCommit002.json"),
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

        let prover_nym = PseudonymSecret::from_hex(
            proof_json["proverNym"]
            .as_str()
            .unwrap()
        ).unwrap();

        let committed_messages: Vec<Vec<u8>> = committed_messages
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect();

        let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

        let (commitment_with_proof_result, secret) =
        Commitment::<BBSplus<S::Ciphersuite>>::commit_with_nym(
            Some(&committed_messages), 
            Some(&prover_nym)
        ).unwrap();

        let commitment_with_proof_result_oct = commitment_with_proof_result.to_bytes();

        assert_eq!(
            hex::encode(&commitment_with_proof_result_oct),
            commitment_with_proof
        );

        assert_eq!(hex::encode(secret.to_bytes()), prover_blind);

        let blind_generators = Generators::create::<S::Ciphersuite>(
            committed_messages.len() + 2,
            Some(&[b"BLIND_", <S::Ciphersuite as BbsCiphersuite>::API_ID_NYM].concat()),
        );

        let result = Commitment::<BBSplus<S::Ciphersuite>>::deserialize_and_validate_commit(
            Some(&commitment_with_proof_result_oct),
            &blind_generators,
            Some(<S::Ciphersuite as BbsCiphersuite>::API_ID_NYM),
        )
        .is_ok();

        assert_eq!(result, expected_result);
    } 

    macro_rules! sign_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { blind_sign_with_nym::<$t>($p, $f); }
        )+)+ }
    }

    sign_tests! {
        (BbsBls12381Sha256, "./fixture_data_nym/bls12-381-sha-256/"): {
            (blind_sign_with_nym_sha256_1, "nymSignature/nymSignature001.json"),
            (blind_sign_with_nym_sha256_2, "nymSignature/nymSignature002.json"),
            (blind_sign_with_nym_sha256_3, "nymSignature/nymSignature003.json"),
            (blind_sign_with_nym_sha256_4, "nymSignature/nymSignature004.json"),
        },
        (BbsBls12381Shake256, "./fixture_data_nym/bls12-381-shake-256/"): {
            (blind_sign_with_nym_shake256_1, "nymSignature/nymSignature001.json"),
            (blind_sign_with_nym_shake256_2, "nymSignature/nymSignature002.json"),
            (blind_sign_with_nym_shake256_3, "nymSignature/nymSignature003.json"),
            (blind_sign_with_nym_shake256_4, "nymSignature/nymSignature004.json"),
        },
    } 

    fn blind_sign_with_nym<S: Scheme>(pathname: &str, filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
        let proof_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        println!("{}", proof_json["caseName"]);

        let sk_hex = proof_json["signerKeyPair"]["secretKey"].as_str().unwrap();
        let pk_hex = proof_json["signerKeyPair"]["publicKey"].as_str().unwrap();

        let sk = BBSplusSecretKey::from_bytes(&hex::decode(sk_hex).unwrap()).unwrap();
        let pk = BBSplusPublicKey::from_bytes(&hex::decode(pk_hex).unwrap()).unwrap();

        let committed_messages: Option<Vec<String>> =
            proof_json["committedMessages"].as_array().and_then(|cm| {
                cm.iter()
                    .map(|m| serde_json::from_value(m.clone()).unwrap())
                    .collect()
            });
        let prover_blind = proof_json["proverBlind"].as_str().map(|b| {
            BlindFactor::from_bytes(&hex::decode(b).unwrap().try_into().unwrap()).unwrap()
        });

        let commitment_with_proof = proof_json["commitmentWithProof"]
            .as_str()
            .map(|c| hex::decode(c).unwrap());

        let committed_messages: Option<Vec<Vec<u8>>> = match committed_messages {
            Some(cm) => Some(cm.iter().map(|m| hex::decode(m).unwrap()).collect()),
            None => None,
        };

        let header = hex::decode(proof_json["header"].as_str().unwrap()).unwrap();
        let messages: Vec<String> = proof_json["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| serde_json::from_value(m.clone()).unwrap())
            .collect(); 
        let messages: Vec<Vec<u8>> = messages.iter().map(|m| hex::decode(m).unwrap()).collect();

        let signer_nym_entropy = PseudonymSecret::from_hex(
            proof_json["signer_nym_entropy"]
            .as_str()
            .unwrap()
        ).unwrap();
        
        let signature = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign_with_nym(
            &sk,
            &pk,
            commitment_with_proof.as_deref(),
            Some(&header),
            &signer_nym_entropy,
            Some(&messages),
        )
        .unwrap();
        let expected_signature = proof_json["signature"].as_str().unwrap();
        let signature_oct = signature.to_bytes();

        assert_eq!(hex::encode(&signature_oct), expected_signature);

/*         let result = signature
            .verify_blind_sign(
                &pk,
                Some(&header),
                Some(&messages),
                committed_messages.as_deref(),
                prover_blind.as_ref(),
            )
            .is_ok();

        let expected_result = proof_json["result"]["valid"].as_bool().unwrap(); 

        assert_eq!(result, expected_result);*/
    }
}






