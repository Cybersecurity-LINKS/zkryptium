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
    BlindProofGenInput, BlindProofVerifyInput,
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

impl zeroize::Zeroize for PseudonymSecret {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Overwrites the secret with zero when the value is dropped (best effort: copies made
/// before, e.g. by `Clone` or by moves, are not erased).
impl Drop for PseudonymSecret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for PseudonymSecret {}

impl From<PseudonymSecret> for BBSplusMessage {
    fn from(val: PseudonymSecret) -> Self {
        BBSplusMessage::new(val.0)
    }
}

impl<'b> Add<&'b PseudonymSecret> for &PseudonymSecret {
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
    ///   If not supplied it defaults to the empty array.
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
///   If not supplied it defaults to the empty array.
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

/// Optional inputs of
/// [`BlindSignature::verify_finalize_with_nym`](crate::schemes::generics::BlindSignature::verify_finalize_with_nym).
/// Every field defaults to empty, none or zero.
#[derive(Clone, Copy, Debug, Default)]
pub struct VerifyFinalizeWithNymInput<'a> {
    /// An octet string containing context and application specific information.
    pub header: Option<&'a [u8]>,
    /// The messages supplied by the Signer.
    pub messages: &'a [Message],
    /// The messages committed by the Prover.
    pub blind_messages: &'a [Message],
    /// The Signer nym entropy. Defaults to zero.
    pub signer_nym_entropy: Option<&'a PseudonymSecret>,
    /// The Prover blind factor returned by the commitment. Defaults to zero.
    pub secret_prover_blind: Option<&'a BlindFactor>,
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
    ///   and commitment_proof, as the first element outputted
    ///   by the `commit_with_nym` operation. If not supplied,
    ///   it defaults to the empty string ("").
    /// * `length_nym_vector` (REQUIRED), the length of the prover_nyms secret vector.
    /// * `header` (OPTIONAL), an octet string containing context and application-specific information.
    /// * `signer_nym_entropy` (REQUIRED), a [`PseudonymSecret`] value
    /// * `messages` (OPTIONAL), a vector of [`Message`]. If not supplied,
    ///   it defaults to the empty array.
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
    /// * `prover_nyms` (REQUIRED), a vector of scalar values ([`PseudonymSecret`]).
    /// * `input`, a [`VerifyFinalizeWithNymInput`] holding the OPTIONAL inputs below.
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    /// * `messages` (OPTIONAL), a vector of [`Message`] supplied by the Signer.
    ///   If not supplied, it defaults to the empty array.
    /// * `blind_messages` (OPTIONAL), a vector of [`Message`] messages committed by the Prover.
    /// * `signer_nym_entropy` (OPTIONAL), a scalar value ([`PseudonymSecret`]).
    ///   If not supplied it defaults to zero "0"
    /// * `secret_prover_blind` (OPTIONAL), a scalar value ([`BlindFactor`]).
    ///   If not supplied it defaults to zero "0"
    ///
    /// # Output:
    /// * `nym_secrets`, a vector of scalar values ([`PseudonymSecret`]) or [`Error`].
    pub fn verify_finalize_with_nym(
        &self,
        pk: &BBSplusPublicKey,
        prover_nyms: Vec<PseudonymSecret>,
        input: VerifyFinalizeWithNymInput<'_>,
    ) -> Result<Vec<PseudonymSecret>, Error> {
        let VerifyFinalizeWithNymInput {
            header,
            messages,
            blind_messages,
            signer_nym_entropy,
            secret_prover_blind,
        } = input;

        let api_id: &[u8] = CS::API_ID_NYM;
        let secret_prover_blind = secret_prover_blind.map_or(Scalar::ZERO, |b| b.0);
        let zero_entropy = PseudonymSecret(Scalar::ZERO);
        let signer_nym_entropy = signer_nym_entropy.unwrap_or(&zero_entropy);
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

        proof_scalars.push(secret_prover_blind);
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
    /// * `nym_secrets` (REQUIRED), the non-empty vector of nym secrets known to the Prover
    ///   (returned by `verify_finalize_with_nym`).
    /// * `context_id` (REQUIRED), an octet string, the context the pseudonym is bound to.
    /// * `input`, a [`BlindProofGenInput`] holding the OPTIONAL inputs below.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `issuer_messages` (OPTIONAL), a vector of [`Message`]. If not supplied, it defaults to
    ///   the empty array.
    /// * `blind_messages` (OPTIONAL), a vector of [`Message`] committed by the Prover. If not
    ///   supplied, it defaults to the empty array.
    /// * `issuer_message_disclosures` (OPTIONAL), vector of [`Disclosure`](super::proof::Disclosure), one per issuer
    ///   message. If not supplied, it defaults to the
    ///   empty vector.
    /// * `blind_message_disclosures` (OPTIONAL), vector of [`Disclosure`](super::proof::Disclosure), one per blind message.
    ///   If not supplied, it defaults to the empty vector.
    /// * `secret_prover_blind` (OPTIONAL), a [`BlindFactor`]. If not supplied it defaults to zero.
    ///
    /// # Output:
    /// ([`BlindPoKSignature::BBSplus`], [`BBSplusPseudonym`], [`AddZkpInfo`]) or [`Error`].
    /// The [`AddZkpInfo`] MUST NOT be sent to the Verifier.
    ///
    pub fn proof_gen_with_nym(
        pk: &BBSplusPublicKey,
        signature: &[u8],
        nym_secrets: &[PseudonymSecret],
        context_id: &[u8],
        input: BlindProofGenInput<'_>,
    ) -> Result<(Self, BBSplusPseudonym, AddZkpInfo), Error> {
        let BlindProofGenInput {
            header,
            ph,
            issuer_messages,
            blind_messages,
            issuer_message_disclosures,
            blind_message_disclosures,
            secret_prover_blind,
        } = input;
        let signature = BBSplusSignature::from_bytes(
            signature.try_into().map_err(|_| Error::InvalidSignature)?,
        )?;
        let api_id = CS::API_ID_NYM;
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
    ///   disclosures is the number of [`Disclosure::Commit`](super::proof::Disclosure::Commit) in `message_disclosures`).
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `pseudonym` (REQUIRED), a [`BBSplusPseudonym`].
    /// * `context_id` (REQUIRED), an octet string, the context the pseudonym is bound to.
    /// * `length_nym_vector` (REQUIRED), the length of the Prover's nym secrets vector.
    /// * `input`, a [`BlindProofVerifyInput`] holding the OPTIONAL inputs below.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `issuer_known_messages_no` (OPTIONAL), the number of messages known by the Signer.
    ///   If not supplied it defaults to 0.
    /// * `disclosed_messages` (OPTIONAL), a vector of [`Message`]: the disclosed issuer messages
    ///   followed by the disclosed blind messages, in index order.
    /// * `message_disclosures` (OPTIONAL), a vector of [`Disclosure`](super::proof::Disclosure), one per signed message
    ///   (issuer messages followed by blind messages; the
    ///   `secret_prover_blind` and the nym secrets excluded).
    ///
    /// # Output:
    /// a result: [`Ok`] or [`Error`].
    ///
    pub fn proof_verify_with_nym(
        &self,
        pk: &BBSplusPublicKey,
        pseudonym: &BBSplusPseudonym,
        context_id: &[u8],
        length_nym_vector: usize,
        input: BlindProofVerifyInput<'_>,
    ) -> Result<(), Error> {
        let BlindProofVerifyInput {
            header,
            ph,
            issuer_known_messages_no: L,
            disclosed_messages,
            message_disclosures,
        } = input;
        let proof = self.to_bbsplus_blind_proof();
        let api_id = CS::API_ID_NYM;

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
// Same inputs, in the same order, as the draft procedure it implements.
#[allow(clippy::too_many_arguments)]
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
// Same inputs, in the same order, as the draft procedure it implements.
#[allow(clippy::too_many_arguments)]
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
    // Same checks as `BBSplusPseudonym::from_bytes` (§4.3), for pseudonyms decoded via serde.
    if bool::from(pseudonym.pseudonym.is_identity()) || pseudonym.pseudonym == G1Projective::GENERATOR {
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
mod tests;






