// Copyright 2026 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::fmt::{self, Formatter};
use std::ops::Add;

use bls12_381_plus::{G1Projective, Scalar};
use serde::{Deserialize, Serialize};
use crate::errors::Error;
use crate::schemes::algorithms::BBSplus;
use crate::bbsplus::commitment::{messages_to_scalar, BBSplusCommitment, Message};
use crate::schemes::generics::{BlindPoKSignature, BlindSignature, Commitment};
use crate::utils::message::bbsplus_message::BBSplusMessage;
use crate::utils::util::bbsplus_utils::{get_random, hash_to_scalar, parse_g1_projective, i2osp, ScalarExt};
use crate::utils::util::get_remaining_indexes;
#[cfg(not(test))]
use crate::utils::util::bbsplus_utils::calculate_random_scalars;
#[cfg(test)]
use crate::utils::util::bbsplus_utils::seeded_random_scalars;
use super::blind::{calculate_b, finalize_blind_sign};
use super::ciphersuites::BbsCiphersuite;
use super::commitment::{core_commit, BlindFactor};
use super::generators::Generators;
use super::keys::{BBSplusPublicKey, BBSplusSecretKey};
use super::proof::{
    blind_proof_challenge_calculate, commitments_proof_finalize, commitments_proof_init,
    commitments_verify_init, proof_finalize, proof_init_with_scalars, proof_verify_init, split,
    validate_disclosure_indexes, verify_proof_pairing, AddZkpInfo, BBSplusBlindPoKSignature,
    Disclosure,
};
use super::signature::{core_verify, BBSplusSignature};
use bls12_381_plus::group::Curve;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PseudonymProofInitResult {
    pseudonym: G1Projective,
    context_id: Vec<u8>,
    Ut: G1Projective
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a BBS+ Pseudonym: a point of G1 different from the identity and from the base
/// point BP1.
/// See <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-4.3>
pub struct BBSplusPseudonym{
    pseudonym: G1Projective
}

impl BBSplusPseudonym {
    /// Converts the `BBSplusPseudonym` to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.pseudonym.to_affine().to_compressed());
        bytes
    }

    /// Creates a `BBSplusPseudonym` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the serialized `BBSplusPseudonym`.
    ///
    /// # Returns
    ///
    /// * `Result<Self, Error>` - A result containing the deserialized `BBSplusPseudonym` or
    ///   [`Error::InvalidPseudonym`] if the bytes are not a valid point of G1, or the point is the
    ///   identity or the base point BP1 (draft-irtf-cfrg-bbs-per-verifier-linkability-05 §4.3).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != G1Projective::COMPRESSED_BYTES {
            return Err(Error::InvalidPseudonym);
        }

        let pseudonym = parse_g1_projective(bytes).map_err(|_| Error::InvalidPseudonym)?;

        if bool::from(pseudonym.is_identity()) || pseudonym == G1Projective::GENERATOR {
            return Err(Error::InvalidPseudonym);
        }

        Ok(Self{pseudonym})
    }
}

#[derive(Debug, PartialEq, Clone, Deserialize)]
/// A struct representing a pseudonym secret factor used in BBS+ pseudonyms.
pub struct PseudonymSecret(pub(crate) Scalar);

impl PseudonymSecret {
    /// Generates a random PseudonymSecret.
    pub fn random() -> Self {
        Self(get_random())
    }

    /// Generates a random vector of PseudonymSecrets.
    /// # Arguments
    ///
    /// * `size` - Number of PseudonymSecret.
    pub fn random_vec(size: usize) -> Vec<Self> {
        let mut secrets = Vec::with_capacity(size);

        for _ in 0..size {
            secrets.push(Self(get_random()))
        }

        secrets
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

    /// Converts a hex string to a PseudonymSecret.
    ///
    /// # Arguments
    ///
    /// * `hex` - Exactly 64 hex characters: the big-endian encoding of a scalar smaller than `r`.
    ///
    /// # Returns
    ///
    /// * A result containing the `PseudonymSecret` or [`Error::InvalidPseudonym`].
    pub fn from_hex(hex: &str) -> Result<Self, Error> {
        // `Scalar::from_be_hex` panics on short or non-hex input and silently ignores trailing
        // characters: decode and check the length here, so untrusted input only yields an error.
        let bytes: [u8; 32] = hex::decode(hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(Error::InvalidPseudonym)?;
        let scalar = Scalar::from_be_bytes(&bytes).into_option().ok_or(Error::InvalidPseudonym)?;
        Ok(Self(scalar))
    }

}

impl Into<BBSplusMessage> for PseudonymSecret {
    fn into(self) -> BBSplusMessage {
        BBSplusMessage::new(self.0)
    }
}

impl<'a, 'b> Add<&'b PseudonymSecret> for &'a PseudonymSecret {
    type Output = PseudonymSecret;

    #[inline]
    fn add(self, rhn: &'b PseudonymSecret) -> PseudonymSecret {
        PseudonymSecret(self.0 + rhn.0)
    }
}

impl fmt::Display for PseudonymSecret {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl<CS: BbsCiphersuite> Commitment<BBSplus<CS>>{
    /// # Description
    /// This operation is used by the Prover to create a commitment to a set of
    /// messages (committed_messages), that they intend to include to the blind signature.
    /// Note that this operation returns both the serialized combination of the commitment
    /// and its proof of correctness (commitment_with_proof), as well as the random scalar used to
    /// blind the commitment (secret_prover_blind). They will also choose their part of
    /// the pseudonym secret prover_nym as a random scalar value
    ///
    /// # Inputs:
    /// * `blind_messages` (OPTIONAL), a vector of [Message].
    ///                                 If not supplied it defaults to the empty array.
    /// * `prover_nyms` (REQUIRED), a non-empty vector of [`PseudonymSecret`].
    ///
    /// # Output:
    /// ([`Commitment::BBSplus`], [`BlindFactor`]),
    ///   a tuple (**`commitment_with_proof`**, **`secret_prover_blind`**) or [`Error`]
    ///   ([`Error::InvalidNymSecretsLength`] if `prover_nyms` is empty).
    ///
    pub fn commit_with_nym(
        blind_messages: Option<&[Message]>,
        prover_nyms: Vec<PseudonymSecret>
    ) -> Result<(Self, BlindFactor), Error> {
        let (commitment_with_proof, secret) =
            commit_with_nym::<CS>(blind_messages, prover_nyms, Some(CS::API_ID_NYM))?;
        Ok((Self::BBSplus(commitment_with_proof), secret))
    }
        
}


/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-7.1.1>
///
/// # Description
/// CommitWithNym: the Prover chooses a set of messages blind_messages that they want
/// to be included in the signature, without revealing them to the Signer.
/// They also choose their part of the pseudonym secret, prover_nyms, as random scalar values.
///
/// # Inputs:
/// * `blind_messages` (OPTIONAL), a vector of [Message].
///                                 If not supplied it defaults to the empty array.
/// * `prover_nyms` (REQUIRED), a non-empty vector of [`PseudonymSecret`].
/// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string.
///
/// # Output:
/// ([`BBSplusCommitment`], [`BlindFactor`]), a tuple (commitment + proof, secret_prover_blind)
/// or [`Error`].
///
fn commit_with_nym<CS>(
    blind_messages : Option<&[Message]>,
    prover_nyms: Vec<PseudonymSecret>,
    api_id: Option<&[u8]>,
) -> Result<(BBSplusCommitment, BlindFactor), Error>
where
    CS: BbsCiphersuite,
{
    // prover_nyms is REQUIRED: the Signer rejects length_nym_vector < 1 (§8.2), so fail early.
    if prover_nyms.is_empty() {
        return Err(Error::InvalidNymSecretsLength);
    }

    let blind_messages = blind_messages.unwrap_or(&[]);
    let api_id = api_id.unwrap_or(b"");

    // 1. committed_message_scalars = Blind.messages_to_scalars(blind_messages, api_id)
    let mut committed_message_scalars = messages_to_scalar::<CS>(blind_messages, Some(api_id))?;

    // 2. committed_message_scalars.append(prover_nyms)
    committed_message_scalars.extend(prover_nyms.iter().map(|t| t.0));

    // 3. blind_generators = BBS.create_generators(length(committed_message_scalars) + 1, "BLIND_" || api_id)
    let blind_generators: Vec<G1Projective> = Generators::create::<CS>(
        committed_message_scalars.len() + 1,
        Some(&[b"BLIND_", api_id].concat()),
    ).values;

    // 4. return Blind.CoreCommit(committed_message_scalars, blind_generators, api_id)
    core_commit::<CS>(blind_generators, Some(committed_message_scalars), Some(api_id))
}

impl<CS: BbsCiphersuite> BlindSignature<BBSplus<CS>> {
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-7.1.2>
    ///
    /// # Description
    /// The Signer generate a signature from a secret key (SK), the commitment with proof,
    /// the length_nym_vector, the signer_nym_entropy and optionally over a header
    /// and vector of messages using the BlindSignWithNym procedure shown below. The length of
    /// the nym vector parameter MUST be furnished by the prover along with the commitment with proof.
    /// Typically the signer_nym_entropy will be a fresh random scalar,
    /// however in the case of "reissue" of a signature for a prover who wants to keep their
    /// same pseudonymous identity this value can be reused for the same prover if desired.
    ///
    /// # Inputs:
    /// * `sk` (REQUIRED), a secret key
    /// * `pk` (REQUIRED), a public key
    /// * `commitment_with_proof` (OPTIONAL), an octet string, representing a serialized commitment
    ///                                       and commitment_proof, as the first element outputted
    ///                                       by the `commit_with_nym` operation. If not supplied,
    ///                                       it defaults to the empty string ("").
    /// * `length_nym_vector` (REQUIRED), the length of the prover_nyms secret vector.
    /// * `header` (OPTIONAL), an octet string containing context and application-specific information.
    /// * `signer_nym_entropy` (REQUIRED), a [`PseudonymSecret`] value
    /// * `messages` (OPTIONAL), a vector of [`Message`]. If not supplied,
    ///                         it defaults to the empty array.
    ///
    /// # Output:
    /// a [`BlindSignature::BBSplus`] or [`Error`].
    ///
    pub fn blind_sign_with_nym(
        sk: &BBSplusSecretKey,
        pk: &BBSplusPublicKey,
        commitment_with_proof: Option<&[u8]>,
        length_nym_vector: usize,
        header: Option<&[u8]>,
        signer_nym_entropy: &PseudonymSecret,
        messages: Option<&[Message]>,
    ) -> Result<Self, Error> {
        let messages = messages.unwrap_or(&[]);
        let L = messages.len();
        let commitment_with_proof = commitment_with_proof.unwrap_or(&[]);
        let header = header.unwrap_or(&[]);

        // Number of blind generators used by the commitment, if any (see `blind_sign`).
        // The draft derives M from length(commitment_with_proof) alone. Here the commitment is
        // parsed first (format, point, scalars), so a malformed input is rejected before paying
        // for the M + 1 hash-to-curve calls of create_generators. For well-formed inputs M is
        // the same value: commitment_with_proof = C || s^ || m^_1..m^_M || challenge.
        let M = if commitment_with_proof.is_empty() {
            0
        } else {
            BBSplusCommitment::from_bytes(commitment_with_proof)?.proof.m_cap.len()
        };

        // The prover nyms are the last length_nym_vector committed scalars (§7.1.1 step 2), so
        // 1 <= length_nym_vector <= M. Not a step of §7.1.2: without this check the entropy
        // would be added to the generator of a blind message or of secret_prover_blind, and
        // the signature could never be finalized by VerifyFinalizeWithNym.
        if length_nym_vector < 1 || length_nym_vector > M {
            return Err(Error::InvalidNymSecretsLength);
        }

        let generators = Generators::create::<CS>(L + 1, Some(CS::API_ID_NYM));

        let blind_generators =
            Generators::create::<CS>(M + 1, Some(&[b"BLIND_", CS::API_ID_NYM].concat()));

        let commitment = Commitment::<BBSplus<CS>>::deserialize_and_validate_commit(
            Some(commitment_with_proof),
            &blind_generators,
            Some(CS::API_ID_NYM)
        )?;
        
        let message_scalars = messages_to_scalar::<CS>(
            messages,
            Some(CS::API_ID_NYM)
        )?;

        // blind_generators has M + 1 >= 2 elements (checked above): never empty.
        let nym_generator = blind_generators.last().ok_or(Error::UnespectedError)?;

        let combined_header = [header , &i2osp::<8>(length_nym_vector)[..]].concat();

        let mut B = calculate_b::<CS>(
            pk,
            &generators,
            &blind_generators,
            Some(commitment),
            message_scalars,
            Some(&*combined_header),
            Some(CS::API_ID_NYM)
        )?;

        let mut B_val = B.pop().ok_or(Error::UnespectedError)?;

        // Add in signer nym_entropy to the last prover_nym element
        B_val += nym_generator * signer_nym_entropy.0;

        let blind_sig = finalize_blind_sign::<CS>(
            sk,
            B_val,
            Some(CS::API_ID_NYM),
        )?;

        Ok(Self::BBSplus(blind_sig))
    }

    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-7.1.3>
    ///
    /// # Description
    /// The following operation both verifies the generated blind signature,
    /// as well as calculating and returning the final nym_secret, used to calculate
    /// the pseudonym value during proof generation.
    ///
    /// # Inputs:
    /// * `self`, a blind signature computed with the `blind_sign_with_nym` operation
    /// * `pk` (REQUIRED), a public key
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    /// * `messages` (OPTIONAL), a vector of [`Message`] supplied by the Signer.
    ///                         If not supplied, it defaults to the empty array.
    /// * `blind_messages` (OPTIONAL), a vector of [`Message`] messages committed by the Prover.
    /// * `prover_nyms` (REQUIRED), a vector of scalar values ([`PseudonymSecret`]).
    /// * `signer_nym_entropy` (OPTIONAL), a scalar value ([`PseudonymSecret`]).
    ///                                     If not supplied it defaults to zero "0"
    /// * `secret_prover_blind` (OPTIONAL), a scalar value ([`BlindFactor`]).
    ///                                     If not supplied it defaults to zero "0"
    ///
    /// # Output:
    /// * `nym_secrets`, a vector of scalar values ([`PseudonymSecret`]) or [`Error`].
    pub fn verify_finalize_with_nym(
        &self,
        pk: &BBSplusPublicKey,
        header: Option<&[u8]>,
        messages: Option<&[Message]>,
        blind_messages: Option<&[Message]>,
        prover_nyms: Vec<PseudonymSecret>,
        signer_nym_entropy: Option<&PseudonymSecret>,
        secret_prover_blind: Option<&BlindFactor>,
    ) -> Result<Vec<PseudonymSecret>, Error> {

        let api_id: &[u8] = CS::API_ID_NYM;
        let messages = messages.unwrap_or(&[]);
        let blind_messages = blind_messages.unwrap_or(&[]);
        let secret_prover_blind = secret_prover_blind.unwrap_or(
            &BlindFactor(Scalar::ZERO)
        );
        let signer_nym_entropy = signer_nym_entropy.unwrap_or(
            &PseudonymSecret(Scalar::ZERO)
        );
        let header = header.unwrap_or(&[]);

        let L = messages.len();
        let M = blind_messages.len();
        let N = prover_nyms.len();

        // prover_nyms is REQUIRED (§7.1.3) and nym_secrets[-1] must exist (step 7).
        if N == 0 {
            return Err(Error::InvalidNymSecretsLength);
        }

        let generators = Generators::create::<CS>(L + 1, Some(CS::API_ID_NYM));
        let blind_generators = Generators::create::<CS>(
            M + N + 1,
            Some(&[b"BLIND_", CS::API_ID_NYM].concat())
        );

        let signer_scalars = messages_to_scalar::<CS>(
            messages,
            Some(CS::API_ID_NYM)
        )?;

        let mut blind_message_scalars = messages_to_scalar::<CS>(
            blind_messages,
            Some(CS::API_ID_NYM)
        )?;

        let mut proof_scalars = signer_scalars;

        proof_scalars.push(secret_prover_blind.0);
        proof_scalars.append(&mut blind_message_scalars);

        let mut nym_secrets = prover_nyms.clone();

        // update the last nym by adding signer_nym_entropy
        let last = nym_secrets.last_mut().ok_or(Error::InvalidNymSecretsLength)?;
        let updated = (&*last) + signer_nym_entropy; // uses impl for &PseudonymSecret + &PseudonymSecret
        *last = updated;
        
        let mut proof_scalars = proof_scalars.iter()
                .map(|t| BBSplusMessage::new(*t))
                .collect::<Vec<_>>();

        proof_scalars.extend(
            nym_secrets
            .iter()
            .map(|t| BBSplusMessage::new(t.0))
        );

        let combined_header = [header , &i2osp::<8>(N)[..]].concat();

        core_verify::<CS>(
            pk,
            self.bbsPlusBlindSignature(),
            &proof_scalars,
            // §7.1.3 step 10: generators.append(blind_generators)
            generators.append(blind_generators),
            Some(combined_header.as_slice()),
            Some(api_id),
        ).map(|()| nym_secrets)
    }

}

impl<CS: BbsCiphersuite> BlindPoKSignature<BBSplus<CS>> {
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-7.2>
    ///
    /// # Description
    /// ProofGenWithNym: computes a BBS proof with a pseudonym. The Blind BBS proof (with optional
    /// committed disclosure) is extended with a zero-knowledge proof of correctness of the
    /// pseudonym, i.e., that it is correctly calculated from the (undisclosed) `nym_secrets` and
    /// the `context_id`, and that `nym_secrets` is signed by the Signer.
    ///
    /// # Signature validity
    /// As required by draft-irtf-cfrg-bbs-signatures-15 (Section 3.6.3), `signature` MUST be a
    /// valid signature of the Signer: the Prover MUST verify it with
    /// [`BlindSignature::verify_finalize_with_nym`](crate::schemes::generics::BlindSignature::verify_finalize_with_nym)
    /// when it receives it from the Signer (that function also returns the `nym_secrets` to use
    /// here), otherwise the unlinkability of the generated proofs is not guaranteed. This
    /// function does not verify the signature; if the storage of the signature is not trusted,
    /// it is RECOMMENDED to verify it again before every call.
    ///
    /// # Inputs:
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `signature` (REQUIRED), an octet string.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `nym_secrets` (REQUIRED), the non-empty vector of nym secrets known to the Prover
    ///                             (returned by `verify_finalize_with_nym`).
    /// * `context_id` (REQUIRED), an octet string, the context the pseudonym is bound to.
    /// * `issuer_messages` (OPTIONAL), a vector of [`Message`]. If not supplied, it defaults to
    ///                                 the empty array.
    /// * `blind_messages` (OPTIONAL), a vector of [`Message`] committed by the Prover. If not
    ///                                supplied, it defaults to the empty array.
    /// * `issuer_message_disclosures` (OPTIONAL), vector of [`Disclosure`], one per issuer
    ///                                            message. If not supplied, it defaults to the
    ///                                            empty vector.
    /// * `blind_message_disclosures` (OPTIONAL), vector of [`Disclosure`], one per blind message.
    ///                                           If not supplied, it defaults to the empty vector.
    /// * `secret_prover_blind` (OPTIONAL), a [`BlindFactor`]. If not supplied it defaults to zero.
    ///
    /// # Output:
    /// ([`BlindPoKSignature::BBSplus`], [`BBSplusPseudonym`], [`AddZkpInfo`]) or [`Error`].
    /// The [`AddZkpInfo`] MUST NOT be sent to the Verifier.
    ///
    pub fn proof_gen_with_nym(
        pk: &BBSplusPublicKey,
        signature: &[u8],
        header: Option<&[u8]>,
        ph: Option<&[u8]>,
        nym_secrets: &[PseudonymSecret],
        context_id: &[u8],
        issuer_messages: Option<&[Message]>,
        blind_messages: Option<&[Message]>,
        issuer_message_disclosures: Option<&[Disclosure]>,
        blind_message_disclosures: Option<&[Disclosure]>,
        secret_prover_blind: Option<&BlindFactor>,
    ) -> Result<(Self, BBSplusPseudonym, AddZkpInfo), Error> {
        let signature = BBSplusSignature::from_bytes(
            signature.try_into().map_err(|_| Error::InvalidSignature)?,
        )?;
        let api_id = CS::API_ID_NYM;
        let issuer_messages = issuer_messages.unwrap_or(&[]);
        let blind_messages = blind_messages.unwrap_or(&[]);
        let issuer_message_disclosures = issuer_message_disclosures.unwrap_or(&[]);
        let blind_message_disclosures = blind_message_disclosures.unwrap_or(&[]);
        let secret_prover_blind = secret_prover_blind.map(|b| b.0).unwrap_or(Scalar::ZERO);

        // Deserialization
        // 1-2. L = length(messages); length(issuer_message_disclosures) != L -> INVALID
        let L = issuer_messages.len();
        if issuer_message_disclosures.len() != L {
            return Err(Error::BlindProofGenError(
                "length of issuer_message_disclosures different from number of issuer messages"
                    .to_owned(),
            ));
        }
        // 3-4. M = length(blind_messages); length(blind_message_disclosures) != M -> INVALID
        let M = blind_messages.len();
        if blind_message_disclosures.len() != M {
            return Err(Error::BlindProofGenError(
                "length of blind_message_disclosures different from number of blind messages"
                    .to_owned(),
            ));
        }
        // 5-10. DISCLOSE / COMMIT indexes in ascending order (HIDE is implicit)
        let issuer_idx = split(issuer_message_disclosures);
        let blind_idx = split(blind_message_disclosures);
        // 11. N = length(nym_secrets): REQUIRED, the pseudonym needs at least one secret
        let N = nym_secrets.len();
        if N == 0 {
            return Err(Error::InvalidNymSecretsLength);
        }

        // Procedure
        // 1-2. generators and blind generators
        let generators = Generators::create::<CS>(L + 1, Some(api_id));
        let blind_generators =
            Generators::create::<CS>(M + N + 1, Some(&[b"BLIND_", api_id].concat()));

        // 3-5. proof_scalars = issuer_scalars || secret_prover_blind || blind_scalars || nym_secrets
        let issuer_scalars = messages_to_scalar::<CS>(issuer_messages, Some(api_id))?;
        let blind_scalars = messages_to_scalar::<CS>(blind_messages, Some(api_id))?;
        let proof_scalars: Vec<BBSplusMessage> = issuer_scalars
            .into_iter()
            .chain(core::iter::once(secret_prover_blind))
            .chain(blind_scalars)
            .chain(nym_secrets.iter().map(|n| n.0))
            .map(BBSplusMessage::new)
            .collect();

        // 6-11. indexes in the proof_scalars vector (blind messages are shifted by L + 1).
        // No nym_secret is ever disclosed or committed.
        let proof_disclosed_indexes: Vec<usize> = issuer_idx
            .disclosed
            .iter()
            .copied()
            .chain(blind_idx.disclosed.iter().map(|&j| j + L + 1))
            .collect();
        let proof_commitment_indexes: Vec<usize> = issuer_idx
            .committed
            .iter()
            .copied()
            .chain(blind_idx.committed.iter().map(|&j| j + L + 1))
            .collect();

        // 12-13.
        let (proof, pseudonym, add_zkp_info) = core_proof_gen_with_nym::<CS>(
            pk,
            &signature,
            &generators.append(blind_generators),
            header,
            ph,
            context_id,
            &proof_scalars,
            &proof_disclosed_indexes,
            &proof_commitment_indexes,
            N,
            Some(api_id),
            CS::SEED_MOCKED_SCALAR,
            CS::BLIND_PROOF_DST,
        )?;

        Ok((Self::BBSplus(proof), pseudonym, add_zkp_info))
    }

    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-7.3>
    ///
    /// # Description
    /// ProofVerifyWithNym: validates a BBS proof with a pseudonym, given the Signer's public key,
    /// the pseudonym, the context identifier used to create it, a header and presentation header,
    /// the disclosed messages and how each signed message is presented to the Verifier.
    /// Validating the proof also validates the correctness and ownership by the Prover of the
    /// received pseudonym.
    ///
    /// # Inputs:
    /// * `self`, a proof (see [`BlindPoKSignature::from_bytes`]: the number of committed
    ///   disclosures is the number of [`Disclosure::Commit`] in `message_disclosures`).
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `pseudonym` (REQUIRED), a [`BBSplusPseudonym`].
    /// * `context_id` (REQUIRED), an octet string, the context the pseudonym is bound to.
    /// * `length_nym_vector` (REQUIRED), the length of the Prover's nym secrets vector.
    /// * `issuer_known_messages_no` (OPTIONAL), the number of messages known by the Signer.
    ///                                          If not supplied it defaults to 0.
    /// * `disclosed_messages` (OPTIONAL), a vector of [`Message`]: the disclosed issuer messages
    ///                                    followed by the disclosed blind messages, in index order.
    /// * `message_disclosures` (OPTIONAL), a vector of [`Disclosure`], one per signed message
    ///                                     (issuer messages followed by blind messages; the
    ///                                     `secret_prover_blind` and the nym secrets excluded).
    ///
    /// # Output:
    /// a result: [`Ok`] or [`Error`].
    ///
    pub fn proof_verify_with_nym(
        &self,
        pk: &BBSplusPublicKey,
        header: Option<&[u8]>,
        ph: Option<&[u8]>,
        pseudonym: &BBSplusPseudonym,
        context_id: &[u8],
        length_nym_vector: usize,
        issuer_known_messages_no: Option<usize>,
        disclosed_messages: Option<&[Message]>,
        message_disclosures: Option<&[Disclosure]>,
    ) -> Result<(), Error> {
        let proof = self.to_bbsplus_blind_proof();
        let api_id = CS::API_ID_NYM;
        let L = issuer_known_messages_no.unwrap_or(0);
        let disclosed_messages = disclosed_messages.unwrap_or(&[]);
        let message_disclosures = message_disclosures.unwrap_or(&[]);

        // Deserialization
        // 1-3. proof_msgs_no = undisclosed_msgs_no + length(disclosed_messages)
        let undisclosed_msgs_no = proof.bbs_proof.m_cap.len();
        let proof_msgs_no = undisclosed_msgs_no + disclosed_messages.len();
        // 4.
        if proof_msgs_no == 0 {
            return Err(Error::PoKSVerificationError("proof covers zero messages".to_owned()));
        }
        // CoreProofVerifyWithNym step 18, checked here too so that no generator is created for
        // an invalid length_nym_vector: 1 <= length_nym_vector <= U.
        if length_nym_vector < 1 || length_nym_vector > undisclosed_msgs_no {
            return Err(Error::InvalidNymSecretsLength);
        }
        // 5. total_msgs_no = proof_msgs_no - 1 - length_nym_vector
        let total_msgs_no = proof_msgs_no
            .checked_sub(1 + length_nym_vector)
            .ok_or(Error::InvalidNymSecretsLength)?;
        // 6.
        if L > total_msgs_no {
            return Err(Error::PoKSVerificationError(
                "issuer_known_messages_no greater than the total number of messages".to_owned(),
            ));
        }
        // 7-9. one disclosure value per message (the enum only admits DISCLOSE, HIDE, COMMIT)
        if message_disclosures.len() != total_msgs_no {
            return Err(Error::PoKSVerificationError(
                "length of message_disclosures different from the total number of messages"
                    .to_owned(),
            ));
        }
        // 10-12.
        let idx = split(message_disclosures);
        if idx.disclosed.len() != disclosed_messages.len() {
            return Err(Error::PoKSVerificationError(
                "number of DISCLOSE entries different from number of disclosed messages"
                    .to_owned(),
            ));
        }
        // 13-15. proof_index(i) = i if i < issuer_known_messages_no, i + 1 otherwise
        let proof_index = |i: usize| if i < L { i } else { i + 1 };
        let proof_disclosed_indexes: Vec<usize> =
            idx.disclosed.iter().map(|&i| proof_index(i)).collect();
        let proof_commitment_indexes: Vec<usize> =
            idx.committed.iter().map(|&i| proof_index(i)).collect();

        // Procedure
        // 1-2.
        let generators = Generators::create::<CS>(L + 1, Some(api_id));
        let blind_generators = Generators::create::<CS>(
            total_msgs_no - L + length_nym_vector + 1,
            Some(&[b"BLIND_", api_id].concat()),
        );

        // 3.
        let message_scalars: Vec<BBSplusMessage> =
            messages_to_scalar::<CS>(disclosed_messages, Some(api_id))?
                .into_iter()
                .map(BBSplusMessage::new)
                .collect();

        // 4-5.
        core_proof_verify_with_nym::<CS>(
            pk,
            proof,
            pseudonym,
            context_id,
            length_nym_vector,
            &generators.append(blind_generators),
            header,
            ph,
            &message_scalars,
            &proof_disclosed_indexes,
            &proof_commitment_indexes,
            Some(api_id),
        )
    }
}

/// Checks the nym secrets positions (draft-irtf-cfrg-bbs-per-verifier-linkability-05 §8.1
/// Deserialization step 8, §8.2 Deserialization step 19): the last `length_nym` of the `L`
/// proof scalars are the nym secrets and must be neither disclosed nor committed.
fn nym_secrets_not_revealed(
    disclosed_indexes: &[usize],
    commitment_indexes: &[usize],
    L: usize,
    length_nym: usize,
) -> bool {
    let first_nym = L - length_nym; // callers ensure length_nym <= L
    disclosed_indexes
        .iter()
        .chain(commitment_indexes)
        .all(|&i| i < first_nym)
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-8.1>
///
/// # Description
/// CoreProofGenWithNym: computes a BBS proof, the committed disclosure proof of correctness
/// and a zero-knowledge proof of correctness of the pseudonym, with common randomness and a
/// common challenge. Validating the proof guarantees that the pseudonym is computed from the
/// nym secrets included in the BBS signature.
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `signature` (REQUIRED), a [`BBSplusSignature`].
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `ph` (OPTIONAL), an octet string containing the presentation header.
/// * `context_id` (REQUIRED), an octet string.
/// * `proof_scalars` (REQUIRED), the signed scalars, ending with the nym secrets.
/// * `disclosed_indexes` (REQUIRED), strictly ascending indexes of disclosed messages.
/// * `commitment_indexes` (REQUIRED), strictly ascending indexes of committed messages.
/// * `length_nym_secrets` (REQUIRED), the length of the nym_secrets vector.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// ([`BBSplusBlindPoKSignature`], [`BBSplusPseudonym`], [`AddZkpInfo`]) or [`Error`].
///
fn core_proof_gen_with_nym<CS>(
    pk: &BBSplusPublicKey,
    signature: &BBSplusSignature,
    generators: &Generators,
    header: Option<&[u8]>,
    ph: Option<&[u8]>,
    context_id: &[u8],
    proof_scalars: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    commitment_indexes: &[usize],
    length_nym_secrets: usize,
    api_id: Option<&[u8]>,
    _seed: &[u8],
    _dst: &[u8],
) -> Result<(BBSplusBlindPoKSignature, BBSplusPseudonym, AddZkpInfo), Error>
where
    CS: BbsCiphersuite,
{
    let api_id = api_id.unwrap_or(b"");
    let header = header.unwrap_or(b"");

    // Deserialization
    // 4. L = length(proof_scalars), nym_secrets at the end
    let L = proof_scalars.len();
    if L + 1 > generators.values.len() {
        return Err(Error::NotEnoughGenerators);
    }
    if length_nym_secrets < 1 || length_nym_secrets > L {
        return Err(Error::InvalidNymSecretsLength);
    }
    // 5-7. strictly ascending in 0..L-1 and disjoint
    validate_disclosure_indexes(disclosed_indexes, commitment_indexes, L)
        .map_err(Error::BlindProofGenError)?;
    // 8. no nym_secret is revealed or committed
    if !nym_secrets_not_revealed(disclosed_indexes, commitment_indexes, L, length_nym_secrets) {
        return Err(Error::BlindProofGenError(
            "nym secrets cannot be disclosed or committed".to_owned(),
        ));
    }
    // 9-16.
    let N = commitment_indexes.len();
    let R = disclosed_indexes.len();
    let U = L - R;
    let undisclosed_indexes = get_remaining_indexes(L, disclosed_indexes);

    // Procedure
    // 1-3. all random scalars at once:
    // (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU) | (s_1, ..., s_N) | (s~_1, ..., s~_N)
    #[cfg(not(test))]
    let mut random_scalars = calculate_random_scalars(5 + U + 2 * N);
    #[cfg(test)]
    let mut random_scalars = seeded_random_scalars::<CS>(5 + U + 2 * N, _seed, _dst);

    let s_tilde = random_scalars.split_off(5 + U + N);
    let s = random_scalars.split_off(5 + U);
    let init_random_scalars = random_scalars;
    let m_tilde = init_random_scalars[5..].to_vec();

    // 4. combined_header = header || I2OSP(length_nym_secrets, 8)
    let combined_header = [header, &i2osp::<8>(length_nym_secrets)[..]].concat();

    // 5-6.
    let init_res = proof_init_with_scalars::<CS>(
        pk,
        signature,
        generators,
        Some(&combined_header),
        proof_scalars,
        disclosed_indexes,
        Some(api_id),
        init_random_scalars,
    )?;

    // 7. nym_scalars = proof_scalars[L - length_nym_secrets, L]
    let nym_scalars: Vec<Scalar> = proof_scalars[L - length_nym_secrets..]
        .iter()
        .map(|m| m.value)
        .collect();
    // 8. nym_rands = init_random_scalars[5 + U - length_nym_secrets, 5 + U]: the nym secrets
    //    are the last undisclosed scalars (step 8 above), so their m~ are the last U ones.
    let nym_rands = &m_tilde[U - length_nym_secrets..];

    // 9-11.
    let pseudonym_init_res =
        pseudonym_proof_init::<CS>(context_id, &nym_scalars, nym_rands, api_id)?;

    // 12-17. commitments and their proof of correctness
    let commitment_init_res = commitments_proof_init::<CS>(
        proof_scalars,
        commitment_indexes,
        &undisclosed_indexes,
        &s,
        &s_tilde,
        &m_tilde,
        api_id,
    )?;

    // 18-19.
    let challenge = blind_proof_challenge_calculate::<CS>(
        &init_res,
        &commitment_init_res,
        &[pseudonym_init_res.pseudonym, pseudonym_init_res.Ut],
        ph,
        Some(api_id),
    )?;

    // 20.
    let bbs_proof = proof_finalize(&init_res, challenge)?;

    // 21-25.
    let (proof, add_zkp_info) = commitments_proof_finalize(
        bbs_proof,
        commitment_init_res,
        proof_scalars,
        challenge,
        s,
        &s_tilde,
    );

    let pseudonym = BBSplusPseudonym { pseudonym: pseudonym_init_res.pseudonym };

    Ok((proof, pseudonym, add_zkp_info))
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-8.2>
///
/// # Description
/// CoreProofVerifyWithNym: validates a BBS proof that also includes a pseudonym. Other than the
/// correctness and integrity of the revealed messages, the header and the presentation header,
/// it guarantees that the pseudonym was produced from the context identifier and the signed (but
/// undisclosed) nym secrets of the Prover.
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `proof` (REQUIRED), a [`BBSplusBlindPoKSignature`].
/// * `pseudonym` (REQUIRED), a [`BBSplusPseudonym`], different from the identity of G1.
/// * `context_id` (REQUIRED), an octet string.
/// * `length_nym_vector` (REQUIRED), the length of the nym secrets vector of the Prover.
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `ph` (OPTIONAL), an octet string containing the presentation header.
/// * `disclosed_messages` (REQUIRED), a vector of scalars ([`BBSplusMessage`]). It could be empty.
/// * `disclosed_indexes` (REQUIRED), strictly ascending indexes of disclosed messages.
/// * `commitment_indexes` (REQUIRED), strictly ascending indexes of committed messages.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a result: [`Ok`] or [`Error`].
///
fn core_proof_verify_with_nym<CS>(
    pk: &BBSplusPublicKey,
    proof: &BBSplusBlindPoKSignature,
    pseudonym: &BBSplusPseudonym,
    context_id: &[u8],
    length_nym_vector: usize,
    generators: &Generators,
    header: Option<&[u8]>,
    ph: Option<&[u8]>,
    disclosed_messages: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    commitment_indexes: &[usize],
    api_id: Option<&[u8]>,
) -> Result<(), Error>
where
    CS: BbsCiphersuite,
{
    let api_id = api_id.unwrap_or(b"");
    let header = header.unwrap_or(b"");

    // Deserialization (steps 1-7: pk and proof are already deserialized)
    // A pseudonym is a point of G1 different from the identity (§4.3, input of §8.2).
    if bool::from(pseudonym.pseudonym.is_identity()) {
        return Err(Error::InvalidPseudonym);
    }
    // 8-10.
    let N = proof.commitments.len();
    if proof.commitments_proof.len() != N || commitment_indexes.len() != N {
        return Err(Error::PoKSVerificationError("number of commitments mismatch".to_owned()));
    }
    // 11-14.
    let U = proof.bbs_proof.m_cap.len();
    let R = disclosed_indexes.len();
    if disclosed_messages.len() != R {
        return Err(Error::PoKSVerificationError(
            "number of disclosed messages different from number of disclosed indexes".to_owned(),
        ));
    }
    let L = R + U;
    // 15-17.
    validate_disclosure_indexes(disclosed_indexes, commitment_indexes, L)
        .map_err(Error::PoKSVerificationError)?;
    // 18.
    if length_nym_vector < 1 || length_nym_vector > U {
        return Err(Error::InvalidNymSecretsLength);
    }
    // 19. the nym_secrets occupy the last length_nym_vector positions
    if !nym_secrets_not_revealed(disclosed_indexes, commitment_indexes, L, length_nym_vector) {
        return Err(Error::PoKSVerificationError(
            "nym secrets cannot be disclosed or committed".to_owned(),
        ));
    }
    // 20-24.
    let undisclosed_indexes = get_remaining_indexes(L, disclosed_indexes);

    // Procedure
    // 1. combined_header = header || I2OSP(length_nym_vector, 8)
    let combined_header = [header, &i2osp::<8>(length_nym_vector)[..]].concat();

    // 2-3.
    let init_res = proof_verify_init::<CS>(
        pk,
        &proof.bbs_proof,
        generators,
        Some(&combined_header),
        disclosed_messages,
        disclosed_indexes,
        Some(api_id),
    )?;

    // 4-8.
    let commitment_init_res =
        commitments_verify_init::<CS>(proof, commitment_indexes, &undisclosed_indexes, api_id)?;

    // 9-10. the m^ of the nym secrets are the last length_nym_vector hats
    let cp = proof.bbs_proof.challenge;
    let pseudonym_init_res = pseudonym_proof_verify_init::<CS>(
        pseudonym,
        context_id,
        &proof.bbs_proof.m_cap[U - length_nym_vector..],
        &cp,
        api_id,
    )?;

    // 11.
    let challenge = blind_proof_challenge_calculate::<CS>(
        &init_res,
        &commitment_init_res,
        &[pseudonym_init_res.pseudonym, pseudonym_init_res.Ut],
        ph,
        Some(api_id),
    )?;

    // 12.
    if cp != challenge {
        return Err(Error::PoKSVerificationError("invalid challenge".to_owned()));
    }

    // 13-14.
    verify_proof_pairing(pk, &proof.bbs_proof)
}

/// `OP = hash_to_curve_g1(context_id, api_id)`, `z = hash_to_scalar(context_id, api_id || "VECT_NYM_SECRETS")`
/// and the evaluation `sum_i v[i] * z^i` of each vector in `vectors`
/// (draft-irtf-cfrg-bbs-per-verifier-linkability-05 §8.3.1 steps 1-6, §8.3.2 steps 1-5).
fn pseudonym_poly_eval<CS, const K: usize>(
    context_id: &[u8],
    vectors: [&[Scalar]; K],
    api_id: &[u8],
) -> Result<(G1Projective, [Scalar; K]), Error>
where
    CS: BbsCiphersuite,
{
    let OP = G1Projective::hash::<CS::Expander>(context_id, api_id);
    let z = hash_to_scalar::<CS>(context_id, &[api_id, b"VECT_NYM_SECRETS"].concat())?;

    // Horner's rule: v[0] + z * (v[1] + z * (v[2] + ...))
    let mut evals = [Scalar::ZERO; K];
    for (eval, v) in evals.iter_mut().zip(vectors) {
        if v.is_empty() {
            return Err(Error::InvalidNymSecretsLength);
        }
        *eval = v.iter().rev().fold(Scalar::ZERO, |acc, x| acc * z + x);
    }
    Ok((OP, evals))
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-8.3.1>
///
/// # Inputs:
/// * `context_id` (REQUIRED), an octet string.
/// * `nym_secrets` (REQUIRED), a non-empty slice of [`Scalar`].
/// * `random_scalars` (REQUIRED), a slice of random [`Scalar`] of the same length.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// [`PseudonymProofInitResult`] `(pseudonym, context_id, Ut)` or [`Error`].
fn pseudonym_proof_init<CS>(
    context_id: &[u8],
    nym_secrets: &[Scalar],
    random_scalars: &[Scalar],
    api_id: &[u8],
) -> Result<PseudonymProofInitResult, Error>
where
    CS: BbsCiphersuite,
{
    if random_scalars.len() != nym_secrets.len() {
        return Err(Error::InvalidNymSecretsLength);
    }

    // 1-6.
    let (OP, [poly_eval_pseudo, poly_eval_proof]) =
        pseudonym_poly_eval::<CS, 2>(context_id, [nym_secrets, random_scalars], api_id)?;

    // 7-8.
    let pseudonym = OP * poly_eval_pseudo;
    let Ut = OP * poly_eval_proof;

    // 9.
    if bool::from(pseudonym.is_identity()) || bool::from(Ut.is_identity()) {
        return Err(Error::G1IdentityError);
    }

    // 10.
    Ok(PseudonymProofInitResult { pseudonym, context_id: context_id.to_vec(), Ut })
}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-per-verifier-linkability-05#section-8.3.2>
///
/// # Inputs:
/// * `pseudonym` (REQUIRED), a [`BBSplusPseudonym`].
/// * `context_id` (REQUIRED), an octet string.
/// * `nym_secret_commitments` (REQUIRED), a non-empty slice of [`Scalar`] (the m^ of the nym secrets).
/// * `proof_challenge` (REQUIRED), a [`Scalar`].
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// [`PseudonymProofInitResult`] `(pseudonym, context_id, Uv)` or [`Error`].
fn pseudonym_proof_verify_init<CS>(
    pseudonym: &BBSplusPseudonym,
    context_id: &[u8],
    nym_secret_commitments: &[Scalar],
    proof_challenge: &Scalar,
    api_id: &[u8],
) -> Result<PseudonymProofInitResult, Error>
where
    CS: BbsCiphersuite,
{
    // 1-5.
    let (OP, [poly_eval_proof]) =
        pseudonym_poly_eval::<CS, 1>(context_id, [nym_secret_commitments], api_id)?;

    // 6. Uv = OP * poly_eval_proof - pseudonym * proof_challenge
    let Uv = OP * poly_eval_proof - pseudonym.pseudonym * proof_challenge;

    // 7.
    if bool::from(Uv.is_identity()) {
        return Err(Error::G1IdentityError);
    }

    // 8.
    Ok(PseudonymProofInitResult {
        pseudonym: pseudonym.pseudonym,
        context_id: context_id.to_vec(),
        Ut: Uv,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use bls12_381_plus::{group::Curve, G1Projective, Scalar};
    use crate::{
        bbsplus::{ciphersuites::BbsCiphersuite, commitment::{BlindFactor, Message}, generators::Generators,
                  keys::{BBSplusPublicKey, BBSplusSecretKey},
        proof::{AddZkpInfo, BBSplusBlindPoKSignature, Disclosure},
        pseudonym::{core_proof_gen_with_nym, PseudonymSecret}, signature::BBSplusSignature,
        test_utils::{hex_value, parse_disclosures, read_fixture}},
        schemes::{
            algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
            generics::{BlindPoKSignature, BlindSignature, Commitment},
        },
        utils::{message::bbsplus_message::BBSplusMessage, util::bbsplus_utils::ScalarExt},
    };

    // FROM_BYTES LENGTH VALIDATION

    use crate::{bbsplus::{pseudonym::BBSplusPseudonym, test_utils::{parse_messages, valid_fixture_bytes}}, errors::Error};

    const NYM_FIXTURE_DIRS: [&str; 2] = [
        "./fixture_data/fixture_data_nym/bls12-381-sha-256/nymProof/",
        "./fixture_data/fixture_data_nym/bls12-381-shake-256/nymProof/",
    ];

    fn assert_pseudonym_rejected(bytes: &[u8]) {
        assert!(
            matches!(BBSplusPseudonym::from_bytes(bytes), Err(Error::InvalidPseudonym)),
            "pseudonym of {} bytes should be rejected",
            bytes.len()
        );
    }

    #[test]
    fn pseudonym_from_bytes_round_trip() {
        for dir in NYM_FIXTURE_DIRS {
            for nym in valid_fixture_bytes(dir, "pseudonym") {
                assert_eq!(BBSplusPseudonym::from_bytes(&nym).unwrap().to_bytes(), nym);
            }
        }
    }

    #[test]
    fn pseudonym_from_bytes_rejects_invalid_lengths() {
        // 48 zero bytes have the right length but are not a valid compressed G1 point.
        for len in [0usize, 1, 47, 48, 49, 96] {
            assert_pseudonym_rejected(&vec![0u8; len]);
        }
        for dir in NYM_FIXTURE_DIRS {
            for nym in valid_fixture_bytes(dir, "pseudonym") {
                assert_pseudonym_rejected(&nym[..47]);
                for extra in [1usize, 32] {
                    let mut bytes = nym.clone();
                    bytes.extend(std::iter::repeat(0u8).take(extra));
                    assert_pseudonym_rejected(&bytes);
                }
            }
        }
    }

    macro_rules! commit_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { commit_with_nym::<$t>($p, $f); }
        )+)+ }
    }

    commit_tests! {
        (BbsBls12381Sha256, "./fixture_data/fixture_data_nym/bls12-381-sha-256/"): {
            (commit_sha256_1, "nymCommit/nymCommit001.json"),
            (commit_sha256_2, "nymCommit/nymCommit002.json"),
            (commit_sha256_3, "nymCommit/nymCommit003.json"),
            (commit_sha256_4, "nymCommit/nymCommit004.json"),
        },
        (BbsBls12381Shake256, "./fixture_data/fixture_data_nym/bls12-381-shake-256/"): {
            (commit_shake256_1, "nymCommit/nymCommit001.json"),
            (commit_shake256_2, "nymCommit/nymCommit002.json"),
            (commit_shake256_3, "nymCommit/nymCommit003.json"),
            (commit_shake256_4, "nymCommit/nymCommit004.json"),
        },
    }

    #[test]
    fn pseudonym_secret_from_hex_rejects_malformed_input() {
        let valid = "6830ea571e9fca0194d9ebd5c571369d8b81655afe0bbb9c6f5efe934f699418";
        assert!(PseudonymSecret::from_hex(valid).is_ok());
        let order_r = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";
        for bad in [
            "",
            &valid[1..],                // 63 chars: used to panic
            &valid[2..],                // 31 bytes
            &format!("{valid}00"),      // trailing data: used to be ignored
            &format!("zz{}", &valid[2..]), // not hex: used to panic
            order_r,                    // not < r
        ] {
            assert!(matches!(PseudonymSecret::from_hex(bad), Err(Error::InvalidPseudonym)), "{bad}");
        }
    }

    // prover_nyms is REQUIRED and the Signer rejects length_nym_vector < 1 (draft 05 §8.2).
    fn commit_with_nym_rejects_empty_nyms<S: Scheme>()
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        let blind_messages = [crate::bbsplus::commitment::Message::hash(b"msg".to_vec())];
        for messages in [None, Some(&blind_messages[..])] {
            assert!(matches!(
                Commitment::<BBSplus<S::Ciphersuite>>::commit_with_nym(messages, Vec::new()),
                Err(Error::InvalidNymSecretsLength)
            ));
        }
    }

    #[test]
    fn commit_with_nym_rejects_empty_nyms_sha256() {
        commit_with_nym_rejects_empty_nyms::<BbsBls12381Sha256>();
    }

    #[test]
    fn commit_with_nym_rejects_empty_nyms_shake256() {
        commit_with_nym_rejects_empty_nyms::<BbsBls12381Shake256>();
    }

    fn commit_with_nym<S: Scheme>(pathname: &str, filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        let proof_json = read_fixture(&[pathname, filename].concat());
        println!("{}", proof_json["caseName"]);

        let prover_blind = proof_json["proverBlind"].as_str().unwrap();
        let commitment_with_proof = proof_json["commitmentWithProof"].as_str().unwrap();

        let prover_nyms = get_pseudonymsecrets(&proof_json, "proverNyms");

        let prover_nyms_len = prover_nyms.len();

        let blind_messages = parse_messages(&proof_json["blindMessages"]);

        let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

        let (commitment_with_proof_result, secret) =
        Commitment::<BBSplus<S::Ciphersuite>>::commit_with_nym(
            Some(&blind_messages),
            prover_nyms
        ).unwrap();

        let commitment_with_proof_result_oct = commitment_with_proof_result.to_bytes();

        assert_eq!(
            hex::encode(&commitment_with_proof_result_oct),
            commitment_with_proof
        );

        assert_eq!(hex::encode(secret.to_bytes()), prover_blind);

        // §7.1.1 step 3: M + 1 generators, with M = blind messages + prover nyms.
        let blind_generators = Generators::create::<S::Ciphersuite>(
            blind_messages.len() + prover_nyms_len + 1,
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
        (BbsBls12381Sha256, "./fixture_data/fixture_data_nym/bls12-381-sha-256/"): {
            (blind_sign_with_nym_sha256_1, "nymSignature/nymSignature001.json"),
            (blind_sign_with_nym_sha256_2, "nymSignature/nymSignature002.json"),
            (blind_sign_with_nym_sha256_3, "nymSignature/nymSignature003.json"),
            (blind_sign_with_nym_sha256_4, "nymSignature/nymSignature004.json"),
            (blind_sign_with_nym_sha256_5, "nymSignature/nymSignature005.json"),
            (blind_sign_with_nym_sha256_6, "nymSignature/nymSignature006.json"),
            (blind_sign_with_nym_sha256_7, "nymSignature/nymSignature007.json"),
        },
        (BbsBls12381Shake256, "./fixture_data/fixture_data_nym/bls12-381-shake-256/"): {
            (blind_sign_with_nym_shake256_1, "nymSignature/nymSignature001.json"),
            (blind_sign_with_nym_shake256_2, "nymSignature/nymSignature002.json"),
            (blind_sign_with_nym_shake256_3, "nymSignature/nymSignature003.json"),
            (blind_sign_with_nym_shake256_4, "nymSignature/nymSignature004.json"),
            (blind_sign_with_nym_shake256_5, "nymSignature/nymSignature005.json"),
            (blind_sign_with_nym_shake256_6, "nymSignature/nymSignature006.json"),
            (blind_sign_with_nym_shake256_7, "nymSignature/nymSignature007.json"),
        },
    }

    // NEGATIVE TESTS: BLIND SIGN / VERIFY FINALIZE WITH NYM

    /// Fixture with 5 blind messages and 10 prover nyms: the commitment has M = 15 scalars.
    const NYM_SIGN_NEGATIVE_FIXTURE: &str = "nymSignature/nymSignature006.json";

    fn nym_sign_negative_cases<S: Scheme>(pathname: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        let json = read_fixture(&[pathname, NYM_SIGN_NEGATIVE_FIXTURE].concat());

        let sk = BBSplusSecretKey::from_bytes(&hex_value(&json["signerKeyPair"]["secretKey"])).unwrap();
        let pk = BBSplusPublicKey::from_bytes(&hex_value(&json["signerKeyPair"]["publicKey"])).unwrap();
        let commitment = hex_value(&json["commitmentWithProof"]);
        let header = hex_value(&json["header"]);
        let messages = parse_messages(&json["messages"]);
        let blind_messages = parse_messages(&json["blindMessages"]);
        let entropy = pseudonym_secret(&json["signer_nym_entropy"]);
        let M = blind_messages.len() + get_pseudonymsecrets(&json, "proverNyms").len();

        let sign = |c: Option<&[u8]>, n: usize| BlindSignature::<BBSplus<S::Ciphersuite>>::
            blind_sign_with_nym(&sk, &pk, c, n, Some(&header), &entropy, Some(&messages));

        // 1 <= length_nym_vector <= M
        for n in [0, M + 1, usize::MAX] {
            assert!(matches!(sign(Some(&commitment), n), Err(Error::InvalidNymSecretsLength)), "n = {n}");
        }
        assert!(sign(Some(&commitment), 1).is_ok());
        assert!(sign(Some(&commitment), M).is_ok());

        // No commitment: there is no prover nym to add the entropy to.
        assert!(matches!(sign(None, 1), Err(Error::InvalidNymSecretsLength)));
        assert!(matches!(sign(Some(&[]), 1), Err(Error::InvalidNymSecretsLength)));

        // Malformed commitment: rejected by the parser, before creating the generators.
        assert!(sign(Some(&commitment[..commitment.len() - 1]), 10).is_err());
        assert!(sign(Some(&commitment[..48]), 1).is_err());

        // VerifyFinalizeWithNym: prover_nyms is REQUIRED.
        let signature = sign(Some(&commitment), 10).unwrap();
        assert!(matches!(
            signature.verify_finalize_with_nym(
                &pk, Some(&header), Some(&messages), Some(&blind_messages),
                Vec::new(), Some(&entropy), None,
            ),
            Err(Error::InvalidNymSecretsLength)
        ));
    }

    #[test]
    fn blind_sign_with_nym_negative_sha256() {
        nym_sign_negative_cases::<BbsBls12381Sha256>("./fixture_data/fixture_data_nym/bls12-381-sha-256/");
    }

    #[test]
    fn blind_sign_with_nym_negative_shake256() {
        nym_sign_negative_cases::<BbsBls12381Shake256>("./fixture_data/fixture_data_nym/bls12-381-shake-256/");
    }

    fn blind_sign_with_nym<S: Scheme>(pathname: &str, filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        let proof_json = read_fixture(&[pathname, filename].concat());
        println!("{}", proof_json["caseName"]);

        let sk = BBSplusSecretKey::from_bytes(&hex_value(&proof_json["signerKeyPair"]["secretKey"])).unwrap();
        let pk = BBSplusPublicKey::from_bytes(&hex_value(&proof_json["signerKeyPair"]["publicKey"])).unwrap();

        let prover_blind = get_blind_factor(&proof_json, "proverBlind");

        let commitment_with_proof = proof_json["commitmentWithProof"]
            .is_string()
            .then(|| hex_value(&proof_json["commitmentWithProof"]));

        let blind_messages = parse_messages(&proof_json["blindMessages"]);

        let header = hex_value(&proof_json["header"]);

        let messages = parse_messages(&proof_json["messages"]);

        let signer_nym_entropy = pseudonym_secret(&proof_json["signer_nym_entropy"]);

        let prover_nyms = get_pseudonymsecrets(&proof_json, "proverNyms");
        
        let signature = BlindSignature::<BBSplus<S::Ciphersuite>>::
        blind_sign_with_nym(
            &sk,
            &pk,
            commitment_with_proof.as_deref(),
            prover_nyms.len(),
            Some(&header),
            &signer_nym_entropy,
            Some(&messages),
        )
        .unwrap();

        let expected_signature = proof_json["signature"].as_str().unwrap();
        let signature_oct = signature.to_bytes();

        assert_eq!(hex::encode(signature_oct), expected_signature);

        let nym_secrets = signature
            .verify_finalize_with_nym(
                &pk,
                Some(&header),
                Some(&messages),
                Some(&blind_messages),
                prover_nyms,
                Some(&signer_nym_entropy),
                prover_blind.as_ref(),
            ).unwrap();

        let expected_nym_secrets: Vec<PseudonymSecret> = proof_json["nym_secrets"]
            .as_array()
            .unwrap()
            .iter()
            .map(pseudonym_secret)
            .collect::<Vec<PseudonymSecret>>();

        assert_eq!(nym_secrets, expected_nym_secrets);
    }
    
    macro_rules! nym_proof_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { nym_proof_check::<$t>($p, $f); }
        )+)+ }
    }

    nym_proof_tests! {
        (BbsBls12381Sha256, "./fixture_data/fixture_data_nym/bls12-381-sha-256/"): {
            (nym_proof_check_sha256_1, "nymProof/nymProof001.json"),
            (nym_proof_check_sha256_2, "nymProof/nymProof002.json"),
            (nym_proof_check_sha256_3, "nymProof/nymProof003.json"),
            (nym_proof_check_sha256_4, "nymProof/nymProof004.json"),
            (nym_proof_check_sha256_5, "nymProof/nymProof005.json"),
            (nym_proof_check_sha256_6, "nymProof/nymProof006.json"),
            (nym_proof_check_sha256_7, "nymProof/nymProof007.json"),
            (nym_proof_check_sha256_8, "nymProof/nymProof008.json"),
            (nym_proof_check_sha256_9, "nymProof/nymProof009.json"),
            (nym_proof_check_sha256_10, "nymProof/nymProof010.json"),
            (nym_proof_check_sha256_11, "nymProof/nymProof011.json"),
            (nym_proof_check_sha256_101, "nymProof/nymProof101.json"),
            (nym_proof_check_sha256_102, "nymProof/nymProof102.json"),
            (nym_proof_check_sha256_103, "nymProof/nymProof103.json"),
            (nym_proof_check_sha256_104, "nymProof/nymProof104.json"),
            (nym_proof_check_sha256_105, "nymProof/nymProof105.json"),
        },
        (BbsBls12381Shake256, "./fixture_data/fixture_data_nym/bls12-381-shake-256/"): {
            (nym_proof_check_shake256_1, "nymProof/nymProof001.json"),
            (nym_proof_check_shake256_2, "nymProof/nymProof002.json"),
            (nym_proof_check_shake256_3, "nymProof/nymProof003.json"),
            (nym_proof_check_shake256_4, "nymProof/nymProof004.json"),
            (nym_proof_check_shake256_5, "nymProof/nymProof005.json"),
            (nym_proof_check_shake256_6, "nymProof/nymProof006.json"),
            (nym_proof_check_shake256_7, "nymProof/nymProof007.json"),
            (nym_proof_check_shake256_8, "nymProof/nymProof008.json"),
            (nym_proof_check_shake256_9, "nymProof/nymProof009.json"),
            (nym_proof_check_shake256_10, "nymProof/nymProof010.json"),
            (nym_proof_check_shake256_11, "nymProof/nymProof011.json"),
            (nym_proof_check_shake256_101, "nymProof/nymProof101.json"),
            (nym_proof_check_shake256_102, "nymProof/nymProof102.json"),
            (nym_proof_check_shake256_103, "nymProof/nymProof103.json"),
            (nym_proof_check_shake256_104, "nymProof/nymProof104.json"),
            (nym_proof_check_shake256_105, "nymProof/nymProof105.json"),
        },
    }

    /// A nym proof test vector together with the inputs of the signature it refers to.
    type NymProofGen<S> = (BlindPoKSignature<BBSplus<<S as Scheme>::Ciphersuite>>, BBSplusPseudonym, AddZkpInfo);

    struct NymProofCase {
        pk: BBSplusPublicKey,
        signature: Vec<u8>,
        header: Vec<u8>,
        ph: Vec<u8>,
        context_id: Vec<u8>,
        nym_secrets: Vec<PseudonymSecret>,
        issuer_messages: Vec<Message>,
        blind_messages: Vec<Message>,
        issuer_disclosures: Vec<Disclosure>,
        blind_disclosures: Vec<Disclosure>,
        secret_prover_blind: Option<BlindFactor>,
        json: Value,
    }

    impl NymProofCase {
        fn load(pathname: &str, proof_filename: &str) -> Self {
            let json = read_fixture(&[pathname, proof_filename].concat());
            let sig = read_fixture(
                &[pathname, "nymSignature/", json["signatureFile"].as_str().unwrap()].concat(),
            );
            Self {
                pk: BBSplusPublicKey::from_bytes(&hex_value(&json["signerPublicKey"])).unwrap(),
                signature: hex_value(&sig["signature"]),
                header: hex_value(&json["header"]),
                ph: hex_value(&json["presentationHeader"]),
                context_id: hex_value(&json["context_id"]),
                nym_secrets: get_pseudonymsecrets(&sig, "nym_secrets"),
                issuer_messages: parse_messages(&sig["messages"]),
                blind_messages: parse_messages(&sig["blindMessages"]),
                issuer_disclosures: parse_disclosures(&json["messageDisclosures"]),
                blind_disclosures: parse_disclosures(&json["blindMessageDisclosures"]),
                secret_prover_blind: get_blind_factor(&sig, "proverBlind"),
                json,
            }
        }

        fn gen<S: Scheme>(&self) -> Result<NymProofGen<S>, Error>
        where
            S::Ciphersuite: BbsCiphersuite,
        {
            BlindPoKSignature::<BBSplus<S::Ciphersuite>>::proof_gen_with_nym(
                &self.pk,
                &self.signature,
                Some(&self.header),
                Some(&self.ph),
                &self.nym_secrets,
                &self.context_id,
                Some(&self.issuer_messages),
                Some(&self.blind_messages),
                Some(&self.issuer_disclosures),
                Some(&self.blind_disclosures),
                self.secret_prover_blind.as_ref(),
            )
        }

        fn message_disclosures(&self) -> Vec<Disclosure> {
            self.issuer_disclosures.iter().chain(&self.blind_disclosures).copied().collect()
        }

        fn disclosed_messages(&self) -> Vec<Message> {
            self.issuer_messages
                .iter()
                .chain(&self.blind_messages)
                .zip(self.message_disclosures())
                .filter(|(_, d)| *d == Disclosure::Disclose)
                .map(|(m, _)| m.clone())
                .collect()
        }

        fn commitments_count(&self) -> usize {
            self.message_disclosures().iter().filter(|d| **d == Disclosure::Commit).count()
        }

        fn verify<S: Scheme>(
            &self,
            proof: &BlindPoKSignature<BBSplus<S::Ciphersuite>>,
            pseudonym: &BBSplusPseudonym,
        ) -> Result<(), Error>
        where
            S::Ciphersuite: BbsCiphersuite,
        {
            proof.proof_verify_with_nym(
                &self.pk,
                Some(&self.header),
                Some(&self.ph),
                pseudonym,
                &self.context_id,
                self.nym_secrets.len(),
                Some(self.issuer_messages.len()),
                Some(&self.disclosed_messages()),
                Some(&self.message_disclosures()),
            )
        }
    }

    fn nym_proof_check<S: Scheme>(pathname: &str, proof_filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        let case = NymProofCase::load(pathname, proof_filename);
        let json = &case.json;
        println!("{}", json["caseName"]);

        assert_eq!(json["L"].as_u64().unwrap() as usize, case.issuer_messages.len());

        // 5 + U + 2N random scalars (§8.1 step 1)
        let N = case.commitments_count();
        let R = case.disclosed_messages().len();
        let U = case.issuer_messages.len() + 1 + case.blind_messages.len() + case.nym_secrets.len() - R;
        assert_eq!(
            5 + U + 2 * N,
            json["mockRngParameters"]["proof"]["count"].as_u64().unwrap() as usize,
            "random scalars count"
        );

        let (proof, pseudonym, add_zkp_info) = case.gen::<S>().unwrap();

        let trace = &json["trace"];
        let hex_list = |v: &Value| -> Vec<String> {
            v.as_array()
                .map(|a| a.iter().map(|c| c.as_str().unwrap().to_owned()).collect())
                .unwrap_or_default()
        };
        let C_i: Vec<String> = proof
            .to_bbsplus_blind_proof()
            .commitments()
            .iter()
            .map(|c| hex::encode(c.to_affine().to_compressed()))
            .collect();
        assert_eq!(C_i, hex_list(&trace["C_i"]), "commitments C_i");

        let s_i: Vec<String> =
            add_zkp_info.commitment_rands.iter().map(|s| hex::encode(s.to_bytes_be())).collect();
        assert_eq!(s_i, hex_list(&trace["randomScalars"]["s_i"]), "commitment rands s_i");
        let committed: Vec<String> = add_zkp_info
            .committed_message_scalars
            .iter()
            .map(|s| hex::encode(s.to_bytes_be()))
            .collect();
        assert_eq!(
            committed,
            hex_list(&json["add_zkp_info"]["committed_message_scalars"]),
            "add_zkp_info committed_message_scalars"
        );

        assert_eq!(
            hex::encode(pseudonym.to_bytes()),
            json["pseudonym"].as_str().unwrap(),
            "pseudonym"
        );
        assert_eq!(
            hex::encode(proof.to_bbsplus_blind_proof().bbs_proof.challenge.to_bytes_be()),
            trace["challenge"].as_str().unwrap(),
            "challenge"
        );

        let proof_bytes = proof.to_bytes();
        assert_eq!(hex::encode(&proof_bytes), json["proof"].as_str().unwrap(), "proof");

        // octets_to_proof round trip, then verification from the parsed values
        let parsed =
            BlindPoKSignature::<BBSplus<S::Ciphersuite>>::from_bytes(&proof_bytes, N).unwrap();
        assert_eq!(parsed.to_bbsplus_blind_proof(), proof.to_bbsplus_blind_proof());
        let parsed_pseudonym = BBSplusPseudonym::from_bytes(&pseudonym.to_bytes()).unwrap();

        let result = case.verify::<S>(&parsed, &parsed_pseudonym).is_ok();
        assert_eq!(result, json["result"]["valid"].as_bool().unwrap());
    }

    // NEGATIVE TESTS: PROOF GEN / VERIFY WITH NYM
    // Start from nymProof010 (issuer and blind messages disclosed, hidden and committed) and
    // alter one input at a time.

    const NYM_PROOF_DIR: &str = "./fixture_data/fixture_data_nym/bls12-381-sha-256/";
    type NymSha256 = BlindPoKSignature<BBSplus<<BbsBls12381Sha256 as Scheme>::Ciphersuite>>;

    fn nym_negative_case() -> (NymProofCase, NymSha256, BBSplusPseudonym) {
        let case = NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json");
        let (proof, pseudonym, _) = case.gen::<BbsBls12381Sha256>().unwrap();
        // sanity check: the unaltered case verifies, so the failures below are meaningful
        case.verify::<BbsBls12381Sha256>(&proof, &pseudonym).unwrap();
        (case, proof, pseudonym)
    }

    #[test]
    fn proof_gen_with_nym_rejects_invalid_inputs() {
        let (case, _, _) = nym_negative_case();

        let mut c = NymProofCase { nym_secrets: vec![], ..NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json") };
        assert!(matches!(c.gen::<BbsBls12381Sha256>(), Err(Error::InvalidNymSecretsLength)));

        // wrong number of disclosures
        c = NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json");
        c.issuer_disclosures.pop();
        assert!(c.gen::<BbsBls12381Sha256>().is_err());
        c = NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json");
        c.blind_disclosures.push(Disclosure::Hide);
        assert!(c.gen::<BbsBls12381Sha256>().is_err());

        // a nym secret vector different from the signed one: the proof does not verify
        c = NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json");
        c.nym_secrets[0] = &c.nym_secrets[0] + &c.nym_secrets[0];
        let (proof, pseudonym, _) = c.gen::<BbsBls12381Sha256>().unwrap();
        assert!(case.verify::<BbsBls12381Sha256>(&proof, &pseudonym).is_err());
    }

    #[test]
    fn core_proof_gen_with_nym_rejects_revealed_nym_secrets() {
        type CS = <BbsBls12381Sha256 as Scheme>::Ciphersuite;
        let (case, _, _) = nym_negative_case();
        let signature = BBSplusSignature::from_bytes(&case.signature.clone().try_into().unwrap()).unwrap();
        let L = case.issuer_messages.len() + 1 + case.blind_messages.len();
        let n = case.nym_secrets.len();
        let api_id = CS::API_ID_NYM;
        let generators = Generators::create::<CS>(case.issuer_messages.len() + 1, Some(api_id)).append(
            Generators::create::<CS>(case.blind_messages.len() + n + 1, Some(&[b"BLIND_", api_id].concat())),
        );
        let scalars: Vec<BBSplusMessage> =
            (0..L + n).map(|i| BBSplusMessage::new(Scalar::from(i as u64 + 1))).collect();
        let gen = |disclosed: &[usize], committed: &[usize], len: usize| {
            core_proof_gen_with_nym::<CS>(
                &case.pk, &signature, &generators, None, None, &case.context_id, &scalars,
                disclosed, committed, len, Some(api_id), CS::SEED_MOCKED_SCALAR, CS::BLIND_PROOF_DST,
            )
        };
        let last = L + n - 1;
        assert!(gen(&[], &[], n).is_ok());
        // the nym secret disclosed or committed
        assert!(gen(&[last], &[], n).is_err());
        assert!(gen(&[], &[last], n).is_err());
        // length_nym_secrets 0 or larger than the scalars
        assert!(matches!(gen(&[], &[], 0), Err(Error::InvalidNymSecretsLength)));
        assert!(matches!(gen(&[], &[], L + n + 1), Err(Error::InvalidNymSecretsLength)));
        // with length 2 the last issuer/blind scalar becomes a nym position
        assert!(gen(&[last - 1], &[], 2).is_err());
    }

    #[test]
    fn proof_verify_with_nym_rejects_wrong_pseudonym_or_context() {
        let (case, proof, _) = nym_negative_case();

        // the pseudonym of another context, or another context for the same pseudonym
        let other = NymProofCase { context_id: b"another context".to_vec(), ..NymProofCase::load(NYM_PROOF_DIR, "nymProof/nymProof010.json") };
        let (other_proof, other_pseudonym, _) = other.gen::<BbsBls12381Sha256>().unwrap();
        assert!(case.verify::<BbsBls12381Sha256>(&proof, &other_pseudonym).is_err());
        assert!(case.verify::<BbsBls12381Sha256>(&other_proof, &other_pseudonym).is_err());
        other.verify::<BbsBls12381Sha256>(&other_proof, &other_pseudonym).unwrap();

        // pseudonym equal to the identity, built in-crate (from_bytes rejects it)
        let identity = BBSplusPseudonym { pseudonym: G1Projective::IDENTITY };
        assert!(matches!(
            case.verify::<BbsBls12381Sha256>(&proof, &identity),
            Err(Error::InvalidPseudonym)
        ));
    }

    #[test]
    fn proof_verify_with_nym_rejects_wrong_length_nym_vector() {
        let (case, proof, pseudonym) = nym_negative_case();
        let U = proof.to_bbsplus_blind_proof().bbs_proof.m_cap.len();
        for n in [0, 2, U, U + 1, usize::MAX] {
            let res = proof.proof_verify_with_nym(
                &case.pk, Some(&case.header), Some(&case.ph), &pseudonym, &case.context_id, n,
                Some(case.issuer_messages.len()), Some(&case.disclosed_messages()),
                Some(&case.message_disclosures()),
            );
            assert!(res.is_err(), "length_nym_vector = {n}");
        }
    }

    #[test]
    fn proof_verify_with_nym_rejects_wrong_disclosures() {
        let (case, proof, pseudonym) = nym_negative_case();
        let verify = |L: usize, disclosed: &[Message], disclosures: &[Disclosure], ph: &[u8]| {
            proof.proof_verify_with_nym(
                &case.pk, Some(&case.header), Some(ph), &pseudonym, &case.context_id,
                case.nym_secrets.len(), Some(L), Some(disclosed), Some(disclosures),
            )
        };
        let L = case.issuer_messages.len();
        let disclosed = case.disclosed_messages();
        let disclosures = case.message_disclosures();
        verify(L, &disclosed, &disclosures, &case.ph).unwrap();

        // issuer_known_messages_no
        assert!(verify(L - 1, &disclosed, &disclosures, &case.ph).is_err());
        assert!(verify(L + 1, &disclosed, &disclosures, &case.ph).is_err());
        assert!(verify(usize::MAX, &disclosed, &disclosures, &case.ph).is_err());

        // a COMMIT moved to another hidden index: same count, wrong binding
        let mut moved = disclosures.clone();
        let i = moved.iter().position(|d| *d == Disclosure::Commit).unwrap();
        let j = moved.iter().position(|d| *d == Disclosure::Hide).unwrap();
        moved.swap(i, j);
        assert!(verify(L, &disclosed, &moved, &case.ph).is_err());

        // wrong length
        let mut short = disclosures.clone();
        short.pop();
        assert!(verify(L, &disclosed, &short, &case.ph).is_err());

        // wrong disclosed message, missing message, other ph
        let mut wrong = disclosed.clone();
        wrong[0] = Message::hash(b"not the signed message".to_vec());
        assert!(verify(L, &wrong, &disclosures, &case.ph).is_err());
        let mut missing = disclosed.clone();
        missing.pop();
        assert!(verify(L, &missing, &disclosures, &case.ph).is_err());
        assert!(verify(L, &disclosed, &disclosures, b"another ph").is_err());
    }

    #[test]
    fn proof_verify_with_nym_rejects_tampered_proof() {
        let (case, proof, pseudonym) = nym_negative_case();
        let tampered = |f: &dyn Fn(&mut BBSplusBlindPoKSignature)| {
            let mut inner = proof.to_bbsplus_blind_proof().clone();
            f(&mut inner);
            NymSha256::BBSplus(inner)
        };
        // commitments, their proof of correctness and the m^ of the nym secret
        for p in [
            tampered(&|p| p.commitments[0] = G1Projective::GENERATOR),
            tampered(&|p| p.commitments.swap(0, 1)),
            tampered(&|p| p.commitments_proof[0] += Scalar::ONE),
            tampered(&|p| *p.bbs_proof.m_cap.last_mut().unwrap() += Scalar::ONE),
        ] {
            assert!(case.verify::<BbsBls12381Sha256>(&p, &pseudonym).is_err());
        }
    }

    #[test]
    fn pseudonym_from_bytes_rejects_identity_and_base_point() {
        let (_, _, pseudonym) = nym_negative_case();
        assert!(BBSplusPseudonym::from_bytes(&pseudonym.to_bytes()).is_ok());
        for p in [G1Projective::IDENTITY, G1Projective::GENERATOR] {
            assert!(matches!(
                BBSplusPseudonym::from_bytes(&p.to_affine().to_compressed()),
                Err(Error::InvalidPseudonym)
            ));
        }
    }

    fn get_pseudonymsecrets(proof_json: &Value, name: &str) -> Vec<PseudonymSecret>{
        let nym_secrets: Vec<PseudonymSecret> = proof_json[name]
                .as_array()
                .unwrap()
                .iter()
                .map(pseudonym_secret)
                .collect::<Vec<PseudonymSecret>>();

        nym_secrets
    }





    /// Parses a scalar of the nym vectors. Some draft 05 vectors drop the leading zero of a
    /// scalar (63 hex chars): pad it to 64.
    fn pseudonym_secret(v: &Value) -> PseudonymSecret {
        PseudonymSecret::from_hex(&format!("{:0>64}", v.as_str().unwrap())).unwrap()
    }

    fn get_blind_factor(proof_json:&Value, name: &str) -> Option<BlindFactor> {
        proof_json[name].as_str().map(|b| {
            BlindFactor::from_bytes(&hex::decode(b).unwrap().try_into().unwrap()).unwrap()
        })
    }
}






