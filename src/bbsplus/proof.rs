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

use super::{
    ciphersuites::BbsCiphersuite, generators::Generators, keys::BBSplusPublicKey,
    signature::BBSplusSignature
};
use crate::{
    errors::Error,
    schemes::{algorithms::BBSplus, generics::PoKSignature},
    utils::{
        message::bbsplus_message::BBSplusMessage,
        util::{
            bbsplus_utils::{
                calculate_domain, get_messages, hash_to_scalar, i2osp, parse_g1_projective,
                ScalarExt,
            },
            get_remaining_indexes,
        },
    },
};
use bls12_381_plus::{multi_miller_loop, G1Projective, G2Prepared, G2Projective, Scalar};
use elliptic_curve::{group::Curve, Group};
use serde::{Deserialize, Serialize};
#[cfg(feature = "bbsplus_blind")]
use super::commitment::{messages_to_scalar, BlindFactor, Message};
#[cfg(feature = "bbsplus_blind")]
use crate::schemes::generics::BlindPoKSignature;

#[cfg(not(test))]
use crate::utils::util::bbsplus_utils::calculate_random_scalars;
use crate::utils::util::bbsplus_utils::{get_generators_from_indexes, multi_exponentiation_g1};
#[cfg(test)]
use crate::utils::util::bbsplus_utils::seeded_random_scalars;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// Represents a BBS+ Proof of Knowledge Signature.
pub struct BBSplusPoKSignature {
    pub(crate) Abar: G1Projective,
    pub(crate) Bbar: G1Projective,
    pub(crate) D: G1Projective,
    pub(crate) e_cap: Scalar,
    pub(crate) r1_cap: Scalar,
    pub(crate) r3_cap: Scalar,
    pub(crate) m_cap: Vec<Scalar>,
    pub(crate) challenge: Scalar,
}

impl BBSplusPoKSignature {
    /// Converts the `BBSplusPoKSignature` to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.Abar.to_affine().to_compressed());
        bytes.extend_from_slice(&self.Bbar.to_affine().to_compressed());
        bytes.extend_from_slice(&self.D.to_affine().to_compressed());
        bytes.extend_from_slice(&self.e_cap.to_bytes_be());
        bytes.extend_from_slice(&self.r1_cap.to_bytes_be());
        bytes.extend_from_slice(&self.r3_cap.to_bytes_be());
        self.m_cap
            .iter()
            .for_each(|v| bytes.extend_from_slice(&v.to_bytes_be()));
        bytes.extend_from_slice(&self.challenge.to_bytes_be());
        bytes
    }

    /// Creates a `BBSplusPoKSignature` from a byte slice.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A byte slice representing the serialized `BBSplusPoKSignature`.
    ///
    /// # Returns
    ///
    /// * `Result<Self, Error>` - A result containing the deserialized `BBSplusPoKSignature` or an error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        const G1_LEN: usize = G1Projective::COMPRESSED_BYTES;
        const SCALAR_LEN: usize = Scalar::BYTES;
        // Abar, Bbar, D
        const POINTS_LEN: usize = 3 * G1_LEN;
        // e^, r1^, r3^, challenge (U = 0)
        const MIN_LEN: usize = POINTS_LEN + 4 * SCALAR_LEN;

        // octets_to_proof requires exactly 3 * octet_point_length + (4 + U) * octet_scalar_length bytes
        if bytes.len() < MIN_LEN || !(bytes.len() - POINTS_LEN).is_multiple_of(SCALAR_LEN) {
            return Err(Error::InvalidProofOfKnowledgeSignature);
        }

        let Abar = parse_g1_projective(&bytes[0..48])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
        let Bbar = parse_g1_projective(&bytes[48..96])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
        let D = parse_g1_projective(&bytes[96..144])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;

        // draft-irtf-cfrg-bbs-signatures-15 §4.2.5.5 octets_to_proof step 7:
        // if A_i is INVALID or Identity_G1, return INVALID (Abar, Bbar, D).
        // The subgroup check already ran inside parse_g1_projective, and
        // identity passes it.
        if Abar == G1Projective::IDENTITY
            || Bbar == G1Projective::IDENTITY
            || D == G1Projective::IDENTITY
        {
            return Err(Error::InvalidProofOfKnowledgeSignature);
        }

        let e_cap = Scalar::from_bytes_be(&bytes[144..176])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
        let r1_cap = Scalar::from_bytes_be(&bytes[176..208])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
        let r3_cap = Scalar::from_bytes_be(&bytes[208..240])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;

        let mut m_cap: Vec<Scalar> = Vec::new();

        for chunk in bytes[240..].as_chunks::<32>().0 {
            m_cap.push(
                Scalar::from_bytes_be(chunk)
                    .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?,
            );
        }

        let challenge = m_cap.pop().ok_or(Error::InvalidProofOfKnowledgeSignature)?; //at least the challenge should be present (even if all attributes are disclosed)

        Ok(Self {
            Abar,
            Bbar,
            D,
            e_cap,
            r1_cap,
            r3_cap,
            m_cap,
            challenge,
        })
    }
}


#[cfg(feature = "bbsplus_blind")]
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-proof-generation>
///
/// Each entry corresponds to an issuer or blind message and can take one of the three values
/// DISCLOSE, HIDE and COMMIT. A DISCLOSE value indicates that message will be revealed to the
/// Verifier. Correspondingly, a HIDE value indicates that message will not be disclosed to
/// the Verifier. Finally, a COMMIT value indicates that only a commitment to messages will
/// be disclosed to the Verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum Disclosure {
    /// The message is revealed to the Verifier.
    Disclose,
    /// The message is not revealed to the Verifier.
    Hide,
    /// Only a commitment to the message is revealed to the Verifier.
    Commit,
}

#[cfg(feature = "bbsplus_blind")]
impl TryFrom<&str> for Disclosure {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "DISCLOSE" | "disclose" => Ok(Disclosure::Disclose),
            "HIDE" | "hide" => Ok(Disclosure::Hide),
            "COMMIT" | "commit" => Ok(Disclosure::Commit),
            other => Err(Error::DeserializationError(format!(
                "Invalid disclosure value: {other}"
            ))),
        }
    }
}

#[cfg(feature = "bbsplus_blind")]
/// Indexes (in ascending order) of the DISCLOSE and COMMIT entries of a disclosure vector.
pub(crate) struct DisclosureIndexes {
    pub disclosed: Vec<usize>,
    pub committed: Vec<usize>,
}

#[cfg(feature = "bbsplus_blind")]
/// Returns the indexes of the DISCLOSE and COMMIT entries, both in ascending order.
pub(crate) fn split(d: &[Disclosure]) -> DisclosureIndexes {
    let mut out = DisclosureIndexes { disclosed: vec![], committed: vec![] };
    for (i, x) in d.iter().enumerate() {
        match x {
            Disclosure::Disclose => out.disclosed.push(i),
            Disclosure::Commit => out.committed.push(i),
            Disclosure::Hide => {}
        }
    }
    out // already ordered
}

#[cfg(feature = "bbsplus_blind")]
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-proof-generation>
///
/// Additional information returned by the Prover from [`BlindPoKSignature::blind_proof_gen`],
/// for use in external ZKPs over the disclosed commitments. From these values the disclosed
/// commitments `C_i = Y_0 * commitment_rands[i] + Y_1 * committed_message_scalars[i]` may be
/// recomputed.
///
/// **It should never be exposed, i.e., it is NOT to be sent to the Verifier.**
#[derive(Clone, PartialEq, Eq)]
pub struct AddZkpInfo {
    /// Scalars of the committed messages, in the order of the commitments in the proof.
    pub committed_message_scalars: Vec<Scalar>,
    /// Random scalars `s_i` used to create the respective commitments.
    pub commitment_rands: Vec<Scalar>,
}

#[cfg(feature = "bbsplus_blind")]
impl zeroize::Zeroize for AddZkpInfo {
    fn zeroize(&mut self) {
        self.committed_message_scalars.zeroize();
        self.commitment_rands.zeroize();
    }
}

#[cfg(feature = "bbsplus_blind")]
/// Overwrites the secret scalars with zero when the value is dropped (best effort).
impl Drop for AddZkpInfo {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

#[cfg(feature = "bbsplus_blind")]
impl zeroize::ZeroizeOnDrop for AddZkpInfo {}

#[cfg(feature = "bbsplus_blind")]
/// Optional inputs of [`BlindPoKSignature::blind_proof_gen`] and
/// [`BlindPoKSignature::proof_gen_with_nym`]. Every field defaults to empty (or none), so
/// only the needed ones have to be set:
///
/// ```ignore
/// BlindProofGenInput {
///     header: Some(header),
///     issuer_messages: &issuer_messages,
///     issuer_message_disclosures: &issuer_message_disclosures,
///     ..Default::default()
/// }
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct BlindProofGenInput<'a> {
    /// An octet string containing context and application specific information.
    pub header: Option<&'a [u8]>,
    /// The presentation header.
    pub ph: Option<&'a [u8]>,
    /// The messages supplied by the Signer.
    pub issuer_messages: &'a [Message],
    /// The messages committed by the Prover.
    pub blind_messages: &'a [Message],
    /// One [`Disclosure`] per issuer message.
    pub issuer_message_disclosures: &'a [Disclosure],
    /// One [`Disclosure`] per blind message.
    pub blind_message_disclosures: &'a [Disclosure],
    /// The Prover blind factor returned by the commitment. Defaults to zero.
    pub secret_prover_blind: Option<&'a BlindFactor>,
}

#[cfg(feature = "bbsplus_blind")]
/// Optional inputs of [`BlindPoKSignature::blind_proof_verify`] and
/// [`BlindPoKSignature::proof_verify_with_nym`]. Every field defaults to empty, none or zero.
#[derive(Clone, Copy, Debug, Default)]
pub struct BlindProofVerifyInput<'a> {
    /// An octet string containing context and application specific information.
    pub header: Option<&'a [u8]>,
    /// The presentation header.
    pub ph: Option<&'a [u8]>,
    /// The number of messages known by the Signer.
    pub issuer_known_messages_no: usize,
    /// The disclosed issuer messages followed by the disclosed blind messages, in index order.
    pub disclosed_messages: &'a [Message],
    /// One [`Disclosure`] per signed message (issuer messages followed by blind messages).
    pub message_disclosures: &'a [Disclosure],
}

#[cfg(feature = "bbsplus_blind")]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// A BBS proof extended with commitments to some of the undisclosed messages, together with
/// the proof of correctness of those commitments
/// (draft-irtf-cfrg-bbs-blind-signatures-05 §4.3.4).
pub struct BBSplusBlindPoKSignature {
    pub(crate) bbs_proof: BBSplusPoKSignature,
    /// Commitments `(C_1, ..., C_N)` to the messages marked as COMMIT.
    pub(crate) commitments: Vec<G1Projective>,
    /// Proof of correctness of the commitments `(s^_1, ..., s^_N)`.
    pub(crate) commitments_proof: Vec<Scalar>,
}

#[cfg(feature = "bbsplus_blind")]
impl BBSplusBlindPoKSignature {
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-proof-to-octets>
    ///
    /// `I2OSP(length(bbs_proof_octs), 8) || bbs_proof_octs || C_1 || ... || C_N || s^_1 || ... || s^_N`
    pub fn to_bytes(&self) -> Vec<u8> {
        let bbs_proof_octs = self.bbs_proof.to_bytes();

        let mut bytes = Vec::with_capacity(
            8 + bbs_proof_octs.len()
                + self.commitments.len() * G1Projective::COMPRESSED_BYTES
                + self.commitments_proof.len() * Scalar::BYTES,
        );
        bytes.extend_from_slice(&i2osp::<8>(bbs_proof_octs.len()));
        bytes.extend_from_slice(&bbs_proof_octs);
        self.commitments
            .iter()
            .for_each(|c| bytes.extend_from_slice(&c.to_affine().to_compressed()));
        self.commitments_proof
            .iter()
            .for_each(|s| bytes.extend_from_slice(&s.to_bytes_be()));
        bytes
    }

    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-octets-to-proof>
    ///
    /// # Inputs:
    /// * `bytes` (REQUIRED), an octet string of the form outputted by [`Self::to_bytes`].
    /// * `commitments_count` (REQUIRED), the number of committed disclosures in the proof.
    pub fn from_bytes(bytes: &[u8], commitments_count: usize) -> Result<Self, Error> {
        const INT_LEN: usize = 8;
        const G1_LEN: usize = G1Projective::COMPRESSED_BYTES;
        const SCALAR_LEN: usize = Scalar::BYTES;

        if bytes.len() < INT_LEN {
            return Err(Error::InvalidProofOfKnowledgeSignature);
        }
        let bbs_proof_len = u64::from_be_bytes(
            bytes[..INT_LEN].try_into().expect("slice of length 8"),
        );
        let bbs_proof_len = usize::try_from(bbs_proof_len)
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;

        let bbs_end = INT_LEN
            .checked_add(bbs_proof_len)
            .ok_or(Error::InvalidProofOfKnowledgeSignature)?;
        if bytes.len() < bbs_end {
            return Err(Error::InvalidProofOfKnowledgeSignature);
        }
        let bbs_proof = BBSplusPoKSignature::from_bytes(&bytes[INT_LEN..bbs_end])?;

        let N = commitments_count;
        let expected_len = commitments_count
            .checked_mul(G1_LEN + SCALAR_LEN)
            .and_then(|l| l.checked_add(bbs_end))
            .ok_or(Error::InvalidProofOfKnowledgeSignature)?;
        if bytes.len() != expected_len {
            return Err(Error::InvalidProofOfKnowledgeSignature);
        }

        let points_end = bbs_end + N * G1_LEN;

        let commitments = bytes[bbs_end..points_end]
            .as_chunks::<G1_LEN>()
            .0
            .iter()
            .map(|c| {
                let C = parse_g1_projective(c)
                    .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
                if C == G1Projective::IDENTITY {
                    return Err(Error::InvalidProofOfKnowledgeSignature);
                }
                Ok(C)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let commitments_proof = bytes[points_end..]
            .as_chunks::<SCALAR_LEN>()
            .0
            .iter()
            .map(|c| {
                let s = Scalar::from_bytes_be(c)
                    .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
                if s == Scalar::ZERO {
                    return Err(Error::InvalidProofOfKnowledgeSignature);
                }
                Ok(s)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(Self {
            bbs_proof,
            commitments,
            commitments_proof,
        })
    }

    /// The commitments `(C_1, ..., C_N)` to the messages marked as COMMIT.
    pub fn commitments(&self) -> &[G1Projective] {
        &self.commitments
    }
}

#[cfg(feature = "bbsplus_blind")]
impl<CS: BbsCiphersuite> BlindPoKSignature<BBSplus<CS>> {
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-proof-generation>
    ///
    /// # Description
    /// This operation creates a BBS proof, which is a zero-knowledge, proof-of-knowledge,
    /// of a BBS signature, while optionally disclosing any subset of the signed messages
    /// (either chosen by the Issuer or committed by the Prover). In addition, this operation
    /// can generate commitments to un-revealed messages and include with the BBS proof that
    /// these commitments correspond to specific un-revealed messages.
    ///
    /// # Signature validity
    /// As required by draft-irtf-cfrg-bbs-signatures-15 (Section 3.6.3), `signature` MUST be a
    /// valid signature of the Signer: the Prover MUST verify it with
    /// [`BlindSignature::verify_blind_sign`](crate::schemes::generics::BlindSignature::verify_blind_sign)
    /// when it receives it from the Signer, otherwise the unlinkability of the generated proofs
    /// is not guaranteed. This function does not verify the signature; if the storage of the
    /// signature is not trusted, it is RECOMMENDED to verify it again before every call.
    ///
    /// # Inputs:
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `signature` (REQUIRED), an octet string.
    /// * `input`, a [`BlindProofGenInput`] holding the OPTIONAL inputs below.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `issuer_messages` (OPTIONAL), a vector of [`Message`]. If not supplied,
    ///   it defaults to the empty array.
    /// * `blind_messages` (OPTIONAL), a vector of [`Message`] committed by the Prover.
    ///   If not supplied, it defaults to the empty array.
    /// * `issuer_message_disclosures` (OPTIONAL), vector of [`Disclosure`], one per issuer
    ///   message. If not supplied, it defaults to
    ///   the empty vector.
    /// * `blind_message_disclosures` (OPTIONAL), vector of [`Disclosure`], one per blind
    ///   message. If not supplied, it defaults to
    ///   the empty vector.
    /// * `secret_prover_blind` (OPTIONAL), a [`BlindFactor`]. If not supplied it defaults to zero.
    ///
    /// # Output:
    /// ([`BlindPoKSignature::BBSplus`], [`AddZkpInfo`]) or [`Error`]. The [`AddZkpInfo`] MUST
    /// NOT be sent to the Verifier.
    ///
    pub fn blind_proof_gen(
        pk: &BBSplusPublicKey,
        signature: &[u8],
        input: BlindProofGenInput<'_>,
    ) -> Result<(Self, AddZkpInfo), Error> {
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
        let api_id = CS::API_ID_BLIND;
        let secret_prover_blind = secret_prover_blind
            .map(|b| b.0)
            .unwrap_or(Scalar::ZERO);

        // Deserialization
        let L = issuer_messages.len();
        if issuer_message_disclosures.len() != L {
            return Err(Error::BlindProofGenError(
                "length of issuer_message_disclosures different from number of issuer messages"
                    .to_owned(),
            ));
        }
        let M = blind_messages.len();
        if blind_message_disclosures.len() != M {
            return Err(Error::BlindProofGenError(
                "length of blind_message_disclosures different from number of blind messages"
                    .to_owned(),
            ));
        }

        let issuer_idx = split(issuer_message_disclosures);
        let blind_idx = split(blind_message_disclosures);

        // Procedure
        let generators = Generators::create::<CS>(L + 1, Some(api_id));
        let blind_generators =
            Generators::create::<CS>(M + 1, Some(&[b"BLIND_", api_id].concat()));

        let issuer_scalars = messages_to_scalar::<CS>(issuer_messages, Some(api_id))?;
        let blind_scalars = messages_to_scalar::<CS>(blind_messages, Some(api_id))?;

        let proof_scalars: Vec<BBSplusMessage> = issuer_scalars
            .into_iter()
            .chain(core::iter::once(secret_prover_blind))
            .chain(blind_scalars)
            .map(BBSplusMessage::new)
            .collect();

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

        let (proof, add_zkp_info) = core_blind_proof_gen::<CS>(
            pk,
            &signature,
            &generators.append(blind_generators),
            header,
            ph,
            &proof_scalars,
            &proof_disclosed_indexes,
            &proof_commitment_indexes,
            Some(api_id),
            CS::SEED_MOCKED_SCALAR,
            CS::BLIND_PROOF_DST,
        )?;

        Ok((Self::BBSplus(proof), add_zkp_info))
    }

    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-proof-verification>
    ///
    /// # Description
    /// The ProofVerify operation validates a BBS proof, given the Signer's public key (PK), a
    /// header and presentation header values, an array of disclosed messages (the ones provided
    /// by the Signer and the ones committed by the prover) and a vector `message_disclosures`
    /// describing how each signed message index is presented to the Verifier. In addition, it
    /// accepts the integer `issuer_known_messages_no`, representing the total number of signed
    /// messages known by the Signer.
    ///
    /// # Inputs:
    /// * `self`, a proof.
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `input`, a [`BlindProofVerifyInput`] holding the OPTIONAL inputs below.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `issuer_known_messages_no` (OPTIONAL), the number of messages known by the Signer.
    ///   If not supplied it defaults to 0.
    /// * `disclosed_messages` (OPTIONAL), a vector of [`Message`]: the disclosed issuer messages
    ///   followed by the disclosed blind messages, in index order.
    /// * `message_disclosures` (OPTIONAL), a vector of [`Disclosure`], one per signed message
    ///   (issuer messages followed by blind messages,
    ///   the `secret_prover_blind` excluded).
    ///
    /// # Output:
    /// a result: [`Ok`] or [`Error`].
    ///
    pub fn blind_proof_verify(
        &self,
        pk: &BBSplusPublicKey,
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
        let api_id = CS::API_ID_BLIND;

        // Deserialization
        let undisclosed_msgs_no = proof.bbs_proof.m_cap.len();
        let proof_msgs_no = undisclosed_msgs_no + disclosed_messages.len();
        if proof_msgs_no == 0 {
            return Err(Error::PoKSVerificationError(
                "proof covers zero messages".to_owned(),
            ));
        }
        let total_msgs_no = proof_msgs_no - 1;
        if L > total_msgs_no {
            return Err(Error::PoKSVerificationError(
                "issuer_known_messages_no greater than the total number of messages".to_owned(),
            ));
        }
        if message_disclosures.len() != total_msgs_no {
            return Err(Error::PoKSVerificationError(
                "length of message_disclosures different from the total number of messages"
                    .to_owned(),
            ));
        }

        let idx = split(message_disclosures);
        if idx.disclosed.len() != disclosed_messages.len() {
            return Err(Error::PoKSVerificationError(
                "number of DISCLOSE entries different from number of disclosed messages"
                    .to_owned(),
            ));
        }

        let proof_index = |i: usize| if i < L { i } else { i + 1 };
        let proof_disclosed_indexes: Vec<usize> =
            idx.disclosed.iter().map(|&i| proof_index(i)).collect();
        let proof_commitment_indexes: Vec<usize> =
            idx.committed.iter().map(|&i| proof_index(i)).collect();

        // Procedure
        let generators = Generators::create::<CS>(L + 1, Some(api_id));
        let blind_generators = Generators::create::<CS>(
            total_msgs_no - L + 1,
            Some(&[b"BLIND_", api_id].concat()),
        );

        let message_scalars: Vec<BBSplusMessage> =
            messages_to_scalar::<CS>(disclosed_messages, Some(api_id))?
                .into_iter()
                .map(BBSplusMessage::new)
                .collect();

        core_blind_proof_verify::<CS>(
            pk,
            proof,
            &generators.append(blind_generators),
            header,
            ph,
            &message_scalars,
            &proof_disclosed_indexes,
            &proof_commitment_indexes,
            Some(api_id),
        )
    }

    /// **Not part of draft-irtf-cfrg-bbs-blind-signatures-05**: convenience helper for
    /// applications that build additional ZKPs on top of the committed disclosure.
    ///
    /// # Description
    /// Returns the two fixed bases `(Y_0, Y_1) = BBS.create_generators(2, "COM_DIS_" || api_id)`
    /// used by [`Self::blind_proof_gen`] for every committed disclosure
    /// `C_i = Y_0 * s_i + Y_1 * m_i`.
    ///
    /// # Why it is useful
    /// The draft computes `Y_0` and `Y_1` internally (§4.3.4, §4.3.5) and never exposes them.
    /// An external ZKP over `C_i` (e.g. a range proof that a committed birth date is before a
    /// given date, draft §1.3) is a statement about the opening `(s_i, m_i)` with respect to these
    /// exact bases: both the Prover, building the external proof, and the Verifier, checking it
    /// against the `C_i` found in the BBS proof, need them. Getting them from here avoids
    /// re-implementing the generator derivation (and its domain separation tag) in the application.
    ///
    /// # Output:
    /// `(Y_0, Y_1)`, two points of G1.
    pub fn committed_disclosure_generators() -> (G1Projective, G1Projective) {
        committed_disclosure_generators::<CS>(CS::API_ID_BLIND)
    }

    /// **Not part of draft-irtf-cfrg-bbs-blind-signatures-05**: convenience helper for
    /// applications that build additional ZKPs on top of the committed disclosure.
    ///
    /// # Description
    /// Recomputes, from the secret [`AddZkpInfo`] returned by [`Self::blind_proof_gen`], the
    /// commitments `C_i = Y_0 * commitment_rands[i] + Y_1 * committed_message_scalars[i]`
    /// (with `(Y_0, Y_1)` from [`Self::committed_disclosure_generators`]), in the same order in
    /// which they appear in the proof ([`BBSplusBlindPoKSignature::commitments`]).
    ///
    /// # Why it is useful
    /// The draft (§4.2.3) states that from `add_zkp_info` "the disclosed commitments may be
    /// recomputed", but it does not define an operation for it. This function is that operation,
    /// and it is the Prover-side bridge between the BBS proof and any external ZKP:
    /// * it ties each opening `(m_i, s_i)` in `add_zkp_info` to the commitment the Verifier will
    ///   see in the proof, so the Prover knows which `C_i` an external proof refers to;
    /// * comparing its output with the commitments of the generated proof is a cheap sanity
    ///   check, before sending anything, that the openings used for the external ZKP are the ones
    ///   actually bound to the signature (if they differ, the external proof would be rejected
    ///   or, worse, would prove a statement about a different value).
    ///
    /// `add_zkp_info` is secret: this function only runs on the Prover side and its inputs must
    /// never be sent to the Verifier. The Verifier only gets the `C_i` from the proof.
    ///
    /// # Inputs:
    /// * `add_zkp_info` (REQUIRED), the [`AddZkpInfo`] returned together with the proof.
    ///
    /// # Output:
    /// a vector of commitments `(C_1, ..., C_N)` or [`Error`] if the two arrays in
    /// `add_zkp_info` have different lengths.
    ///
    /// # Example
    /// ```ignore
    /// let (proof, add_zkp_info) = BlindPoKSignature::<BBSplus<CS>>::blind_proof_gen(/* ... */)?;
    /// let recomputed = BlindPoKSignature::<BBSplus<CS>>::recompute_commitments(&add_zkp_info)?;
    /// assert_eq!(recomputed, proof.to_bbsplus_blind_proof().commitments());
    /// // recomputed[i] can now be used as the public input of an external ZKP whose
    /// // witness is (add_zkp_info.commitment_rands[i], add_zkp_info.committed_message_scalars[i]).
    /// ```
    pub fn recompute_commitments(add_zkp_info: &AddZkpInfo) -> Result<Vec<G1Projective>, Error> {
        if add_zkp_info.committed_message_scalars.len() != add_zkp_info.commitment_rands.len() {
            return Err(Error::BlindProofGenError(
                "add_zkp_info: committed_message_scalars and commitment_rands lengths differ"
                    .to_owned(),
            ));
        }

        let (Y_0, Y_1) = Self::committed_disclosure_generators();

        Ok(add_zkp_info
            .commitment_rands
            .iter()
            .zip(&add_zkp_info.committed_message_scalars)
            .map(|(s, m)| Y_0 * s + Y_1 * m)
            .collect())
    }

    /// Converts the proof to a byte vector (see [`BBSplusBlindPoKSignature::to_bytes`]).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bbsplus_blind_proof().to_bytes()
    }

    /// Creates the proof from a byte slice, given the number of committed disclosures
    /// (see [`BBSplusBlindPoKSignature::from_bytes`]).
    pub fn from_bytes(bytes: &[u8], commitments_count: usize) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusBlindPoKSignature::from_bytes(
            bytes,
            commitments_count,
        )?))
    }

    /// Converts the `BlindPoKSignature` to a [`BBSplusBlindPoKSignature`].
    pub fn to_bbsplus_blind_proof(&self) -> &BBSplusBlindPoKSignature {
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }
}

#[cfg(feature = "bbsplus_blind")]
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-core-proof-generation>
///
/// Result of the initialization of the commitments proof of correctness.
pub(super) struct CommitmentInitRes {
    commitments: Vec<G1Projective>,
    commitments_proofs: Vec<G1Projective>,
    commitment_indexes: Vec<usize>,
}

#[cfg(feature = "bbsplus_blind")]
/// Checks that `indexes` is a strictly ascending list of integers in `0..L`.
fn is_strictly_ascending_in_range(indexes: &[usize], L: usize) -> bool {
    indexes.windows(2).all(|w| w[0] < w[1]) && indexes.last().is_none_or(|&i| i < L)
}

#[cfg(feature = "bbsplus_blind")]
/// Validates disclosed and commitment indexes as required by CoreProofGen / CoreProofVerify:
/// both strictly ascending in `0..L` and disjoint.
pub(super) fn validate_disclosure_indexes(
    disclosed_indexes: &[usize],
    commitment_indexes: &[usize],
    L: usize,
) -> Result<(), String> {
    if !is_strictly_ascending_in_range(commitment_indexes, L) {
        return Err("commitment indexes not strictly ascending in 0..L-1".to_owned());
    }
    if !is_strictly_ascending_in_range(disclosed_indexes, L) {
        return Err("disclosed indexes not strictly ascending in 0..L-1".to_owned());
    }
    if commitment_indexes.iter().any(|i| disclosed_indexes.contains(i)) {
        return Err("disclosed and commitment indexes are not disjoint".to_owned());
    }
    Ok(())
}

#[cfg(feature = "bbsplus_blind")]
/// `(Y_0, Y_1) = BBS.create_generators(2, "COM_DIS_" || api_id)`
pub(super) fn committed_disclosure_generators<CS>(api_id: &[u8]) -> (G1Projective, G1Projective)
where
    CS: BbsCiphersuite,
{
    let Y = Generators::create::<CS>(2, Some(&[b"COM_DIS_", api_id].concat())).values;
    (Y[0], Y[1])
}

#[cfg(feature = "bbsplus_blind")]
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-core-proof-generation>
///
/// # Description
/// Combines the BBS Proof Generation operations (ProofInit and ProofFinalize) with a proof of
/// correctness of commitments over some of the signed messages. The two proofs share a common
/// challenge, returned by [`blind_proof_challenge_calculate`].
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `signature` (REQUIRED), a [`BBSplusSignature`].
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `ph` (OPTIONAL), an octet string containing the presentation header.
/// * `messages` (REQUIRED), a vector of scalars ([`BBSplusMessage`]). It could be empty.
/// * `disclosed_indexes` (REQUIRED), strictly ascending indexes of disclosed messages.
/// * `commitment_indexes` (REQUIRED), strictly ascending indexes of committed messages.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// ([`BBSplusBlindPoKSignature`], [`AddZkpInfo`]) or [`Error`].
///
// Same inputs, in the same order, as the draft procedure it implements.
#[allow(clippy::too_many_arguments)]
fn core_blind_proof_gen<CS>(
    pk: &BBSplusPublicKey,
    signature: &BBSplusSignature,
    generators: &Generators,
    header: Option<&[u8]>,
    ph: Option<&[u8]>,
    messages: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    commitment_indexes: &[usize],
    api_id: Option<&[u8]>,
    _seed: &[u8],
    _dst: &[u8],
) -> Result<(BBSplusBlindPoKSignature, AddZkpInfo), Error>
where
    CS: BbsCiphersuite,
{
    let api_id = api_id.unwrap_or(b"");

    // Deserialization
    let L = messages.len();
    if L + 1 > generators.values.len() {
        return Err(Error::NotEnoughGenerators);
    }
    validate_disclosure_indexes(disclosed_indexes, commitment_indexes, L)
        .map_err(Error::BlindProofGenError)?;

    let N = commitment_indexes.len();
    let R = disclosed_indexes.len();
    let U = L - R;
    let undisclosed_indexes = get_remaining_indexes(L, disclosed_indexes);

    // Procedure
    // Get all necessary random scalars at once
    #[cfg(not(test))]
    let mut random_scalars = calculate_random_scalars(5 + U + 2 * N);
    #[cfg(test)]
    let mut random_scalars = seeded_random_scalars::<CS>(5 + U + 2 * N, _seed, _dst);

    // (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU) | (s_1, ..., s_N) | (s~_1, ..., s~_N)
    let s_tilde = random_scalars.split_off(5 + U + N);
    let s = random_scalars.split_off(5 + U);
    let init_random_scalars = random_scalars;
    let m_tilde = init_random_scalars[5..].to_vec();

    let init_res = proof_init_with_scalars::<CS>(
        pk,
        signature,
        generators,
        header,
        messages,
        disclosed_indexes,
        Some(api_id),
        init_random_scalars,
    )?;

    // Calculate the commitments and initiate the correctness proof
    let commitment_init_res = commitments_proof_init::<CS>(
        messages,
        commitment_indexes,
        &undisclosed_indexes,
        &s,
        &s_tilde,
        &m_tilde,
        api_id,
    )?;

    let challenge = blind_proof_challenge_calculate::<CS>(
        &init_res,
        &commitment_init_res,
        &[],
        ph,
        Some(api_id),
    )?;

    let bbs_proof = proof_finalize(&init_res, challenge)?;

    Ok(commitments_proof_finalize(
        bbs_proof,
        commitment_init_res,
        messages,
        challenge,
        s,
        &s_tilde,
    ))
}

#[cfg(feature = "bbsplus_blind")]
/// Steps 12–17 of the committed disclosure proof generation
/// (draft-irtf-cfrg-bbs-blind-signatures-05 §4.3.4, shared with
/// draft-irtf-cfrg-bbs-per-verifier-linkability-05 §8.1):
///
/// ```text
/// for i in (1, 2, ..., N):
///     idx = commitment_indexes[i]
///     C_i = Y_0 * s_i + Y_1 * proof_scalars[idx]
///     let k be the integer such that j_k == idx
///     C~_i = Y_0 * s~_i + Y_1 * m~_k
/// ```
pub(super) fn commitments_proof_init<CS>(
    messages: &[BBSplusMessage],
    commitment_indexes: &[usize],
    undisclosed_indexes: &[usize],
    s: &[Scalar],
    s_tilde: &[Scalar],
    m_tilde: &[Scalar],
    api_id: &[u8],
) -> Result<CommitmentInitRes, Error>
where
    CS: BbsCiphersuite,
{
    let N = commitment_indexes.len();
    if s.len() != N || s_tilde.len() != N || m_tilde.len() != undisclosed_indexes.len() {
        return Err(Error::BlindProofGenError(
            "inconsistent number of random scalars".to_owned(),
        ));
    }

    let (Y_0, Y_1) = committed_disclosure_generators::<CS>(api_id);

    let mut commitments = Vec::with_capacity(N);
    let mut commitments_proofs = Vec::with_capacity(N);
    for (i, &idx) in commitment_indexes.iter().enumerate() {
        let k = undisclosed_indexes
            .iter()
            .position(|&j| j == idx)
            .ok_or_else(|| {
                Error::BlindProofGenError("committed message is not undisclosed".to_owned())
            })?;
        let m = messages
            .get(idx)
            .ok_or_else(|| Error::BlindProofGenError("commitment index out of range".to_owned()))?;
        commitments.push(Y_0 * s[i] + Y_1 * m.value);
        commitments_proofs.push(Y_0 * s_tilde[i] + Y_1 * m_tilde[k]);
    }

    Ok(CommitmentInitRes {
        commitments,
        commitments_proofs,
        commitment_indexes: commitment_indexes.to_vec(),
    })
}

#[cfg(feature = "bbsplus_blind")]
/// Last steps of the committed disclosure proof generation: `s^_i = s~_i + challenge * s_i`,
/// the proof and the `add_zkp_info` (draft-irtf-cfrg-bbs-blind-signatures-05 §4.3.4, shared with
/// draft-irtf-cfrg-bbs-per-verifier-linkability-05 §8.1 steps 21–24).
pub(super) fn commitments_proof_finalize(
    bbs_proof: BBSplusPoKSignature,
    commitment_init_res: CommitmentInitRes,
    messages: &[BBSplusMessage],
    challenge: Scalar,
    s: Vec<Scalar>,
    s_tilde: &[Scalar],
) -> (BBSplusBlindPoKSignature, AddZkpInfo) {
    let commitments_proof: Vec<Scalar> = s_tilde
        .iter()
        .zip(&s)
        .map(|(st, si)| st + challenge * si)
        .collect();

    let add_zkp_info = AddZkpInfo {
        // indexes already validated by commitments_proof_init
        committed_message_scalars: commitment_init_res
            .commitment_indexes
            .iter()
            .map(|&idx| messages[idx].value)
            .collect(),
        commitment_rands: s,
    };

    let proof = BBSplusBlindPoKSignature {
        bbs_proof,
        commitments: commitment_init_res.commitments,
        commitments_proof,
    };

    (proof, add_zkp_info)
}

#[cfg(feature = "bbsplus_blind")]
/// Steps 4–8 of the committed disclosure proof verification
/// (draft-irtf-cfrg-bbs-blind-signatures-05 §4.3.5, shared with
/// draft-irtf-cfrg-bbs-per-verifier-linkability-05 §8.2):
///
/// ```text
/// for i in (1, 2, ..., N):
///     idx = commitment_indexes[i]
///     let k be the integer such that j_k == idx
///     C^_i = Y_0 * s^_i + Y_1 * m^_k - C_i * cp
/// ```
pub(super) fn commitments_verify_init<CS>(
    proof: &BBSplusBlindPoKSignature,
    commitment_indexes: &[usize],
    undisclosed_indexes: &[usize],
    api_id: &[u8],
) -> Result<CommitmentInitRes, Error>
where
    CS: BbsCiphersuite,
{
    let N = commitment_indexes.len();
    if proof.commitments.len() != N || proof.commitments_proof.len() != N {
        return Err(Error::PoKSVerificationError(
            "number of commitments mismatch".to_owned(),
        ));
    }
    if proof.bbs_proof.m_cap.len() != undisclosed_indexes.len() {
        return Err(Error::PoKSVerificationError(
            "number of undisclosed messages mismatch".to_owned(),
        ));
    }
    // draft-irtf-cfrg-bbs-blind-signatures-05 octets_to_proof: no C_j is Identity_G1 and no
    // s^_j is zero. Repeated here for proofs that do not come from `from_bytes` (serde).
    if proof.commitments.iter().any(|C| bool::from(C.is_identity()))
        || proof.commitments_proof.contains(&Scalar::ZERO)
    {
        return Err(Error::InvalidProofOfKnowledgeSignature);
    }

    let (Y_0, Y_1) = committed_disclosure_generators::<CS>(api_id);
    let cp = proof.bbs_proof.challenge;

    let mut commitments_proofs = Vec::with_capacity(N);
    for (i, &idx) in commitment_indexes.iter().enumerate() {
        let k = undisclosed_indexes
            .iter()
            .position(|&j| j == idx)
            .ok_or_else(|| {
                Error::PoKSVerificationError("committed message is not undisclosed".to_owned())
            })?;
        commitments_proofs.push(
            Y_0 * proof.commitments_proof[i] + Y_1 * proof.bbs_proof.m_cap[k]
                - proof.commitments[i] * cp,
        );
    }

    Ok(CommitmentInitRes {
        commitments: proof.commitments.clone(),
        commitments_proofs,
        commitment_indexes: commitment_indexes.to_vec(),
    })
}

#[cfg(feature = "bbsplus_blind")]
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-core-proof-verification>
///
/// # Description
/// Verifies a BBS proof extended with the proof of correctness of commitments to some of the
/// undisclosed messages.
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `proof` (REQUIRED), a [`BBSplusBlindPoKSignature`].
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
fn core_blind_proof_verify<CS>(
    pk: &BBSplusPublicKey,
    proof: &BBSplusBlindPoKSignature,
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

    // Deserialization
    let N = proof.commitments.len();
    if proof.commitments_proof.len() != N || commitment_indexes.len() != N {
        return Err(Error::PoKSVerificationError(
            "number of commitments mismatch".to_owned(),
        ));
    }
    let U = proof.bbs_proof.m_cap.len();
    let R = disclosed_indexes.len();
    if disclosed_messages.len() != R {
        return Err(Error::PoKSVerificationError(
            "number of disclosed messages different from number of disclosed indexes".to_owned(),
        ));
    }
    let L = R + U;
    validate_disclosure_indexes(disclosed_indexes, commitment_indexes, L)
        .map_err(Error::PoKSVerificationError)?;
    let undisclosed_indexes = get_remaining_indexes(L, disclosed_indexes);

    // Procedure
    let init_res = proof_verify_init::<CS>(
        pk,
        &proof.bbs_proof,
        generators,
        header,
        disclosed_messages,
        disclosed_indexes,
        Some(api_id),
    )?;

    let cp = proof.bbs_proof.challenge;
    let commitment_init_res = commitments_verify_init::<CS>(
        proof,
        commitment_indexes,
        &undisclosed_indexes,
        api_id,
    )?;

    let challenge = blind_proof_challenge_calculate::<CS>(
        &init_res,
        &commitment_init_res,
        &[],
        ph,
        Some(api_id),
    )?;

    if cp != challenge {
        return Err(Error::PoKSVerificationError("invalid challenge".to_owned()));
    }

    verify_proof_pairing(pk, &proof.bbs_proof)
}

#[cfg(feature = "bbsplus_blind")]
/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-proof-challenge-calculation>
///
/// # Description
/// Challenge calculation shared by the BBS proof and the commitments proof of correctness.
///
/// The same procedure is used by the pseudonym proof
/// (draft-irtf-cfrg-bbs-per-verifier-linkability-05 §9.1,
/// `ProofWithPseudonymChallengeCalculate`), which only adds `(pseudonym, Ut)` between `T2`
/// and `domain`: they are passed as `pseudonym_points` (empty for Blind BBS).
///
/// # Inputs:
/// * `init_res` (REQUIRED), [`ProofInitRes`] (holds the disclosed messages and indexes).
/// * `commitment_init_res` (REQUIRED), [`CommitmentInitRes`].
/// * `pseudonym_points` (REQUIRED), `[]` for Blind BBS, `[pseudonym, Ut]` for the pseudonym proof.
/// * `ph` (OPTIONAL), an octet string containing the presentation header.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a challenge ([`Scalar`]) or [`Error`].
///
pub(super) fn blind_proof_challenge_calculate<CS>(
    init_res: &ProofInitRes,
    commitment_init_res: &CommitmentInitRes,
    pseudonym_points: &[G1Projective],
    ph: Option<&[u8]>,
    api_id: Option<&[u8]>,
) -> Result<Scalar, Error>
where
    CS: BbsCiphersuite,
{
    let N = commitment_init_res.commitments.len();
    if commitment_init_res.commitments_proofs.len() != N
        || commitment_init_res.commitment_indexes.len() != N
    {
        return Err(Error::ProofGenError(
            "commitment init result has inconsistent lengths".to_owned(),
        ));
    }

    let api_id = api_id.unwrap_or(b"");
    let challenge_dst = [api_id, CS::H2S].concat();
    let ph = ph.unwrap_or(b"");

    let mut c_octs = proof_challenge_octets(init_res, pseudonym_points)?;

    c_octs.extend_from_slice(&i2osp::<8>(N));
    for ((ci, C), C_tilde) in commitment_init_res
        .commitment_indexes
        .iter()
        .zip(&commitment_init_res.commitments)
        .zip(&commitment_init_res.commitments_proofs)
    {
        c_octs.extend_from_slice(&i2osp::<8>(*ci));
        c_octs.extend_from_slice(&C.to_affine().to_compressed());
        c_octs.extend_from_slice(&C_tilde.to_affine().to_compressed());
    }

    c_octs.extend_from_slice(&i2osp::<8>(ph.len()));
    c_octs.extend_from_slice(ph);

    hash_to_scalar::<CS>(&c_octs, &challenge_dst)
}

impl<CS: BbsCiphersuite> PoKSignature<BBSplus<CS>> {
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-proof-generation-proofgen>
    ///
    /// # Description
    /// The ProofGen operation creates BBS proof, which is a zero-knowledge, proof-of-knowledge of 
    /// a BBS signature, while optionally disclosing any subset of the signed messages. 
    /// Validating the proof guarantees authenticity and integrity of the header and disclosed 
    /// messages, as well as knowledge of a valid BBS signature. Other than the 
    /// Signer's public key (PK), the BBS signature and the signed header and messages, 
    /// the operation also accepts a presentation_header value. That value, chosen by the Prover, 
    /// will also be integrity protected (signed) by the resulting proof. Finally, to indicate 
    /// which of the messages should be disclosed, the operation accepts a list of integers 
    /// in ascending order, representing the indexes of those message
    ///
    /// # Signature validity
    /// As required by draft-irtf-cfrg-bbs-signatures-15 (Section 3.6.3), `signature` MUST be a
    /// valid signature of the Signer: the Prover MUST verify it with
    /// [`Signature::verify`](crate::schemes::generics::Signature::verify) when it receives it
    /// from the Signer, otherwise the unlinkability of the generated proofs is not guaranteed.
    /// This function does not verify the signature; if the storage of the signature is not
    /// trusted, it is RECOMMENDED to verify it again before every call.
    ///
    /// # Inputs:
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `signature` (REQUIRED), an octet string.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `messages` (OPTIONAL), a vector of octet strings representing the signed messages. 
    ///   If not supplied, it defaults to the empty array ("()").
    /// * `disclosed_indexes` (OPTIONAL), vector of unsigned integers in ascending order. 
    ///   Indexes of disclosed messages.
    ///   If not supplied, it defaults to the empty array ("()").
    ///
    /// # Output:
    /// a PoK of a Signature [`PoKSignature::BBSplus`] or [`Error`].
    ///
    pub fn proof_gen(
        pk: &BBSplusPublicKey,
        signature: &[u8],
        header: Option<&[u8]>,
        ph: Option<&[u8]>,
        messages: Option<&[Vec<u8>]>,
        disclosed_indexes: Option<&[usize]>,
    ) -> Result<Self, Error> {
        let signature = BBSplusSignature::from_bytes(
            signature.try_into().map_err(|_| Error::InvalidSignature)?,
        )?;
        let messages = messages.unwrap_or(&[]);
        let disclosed_indexes = disclosed_indexes.unwrap_or(&[]);

        let message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID)?;
        let generators = Generators::create::<CS>(messages.len() + 1, Some(CS::API_ID));

        let proof = core_proof_gen::<CS>(
            pk,
            &signature,
            &generators,
            &message_scalars,
            disclosed_indexes,
            header,
            ph,
            Some(CS::API_ID),
            CS::SEED_MOCKED_SCALAR,
            CS::MOCKED_SCALAR_DST,
        )?;

        Ok(Self::BBSplus(proof))
    }

    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-proof-verification-proofver>
    ///
    /// # Description
    /// The ProofVerify operation validates a BBS proof, given the Signer's public key (PK), 
    /// a header and presentation header values, the disclosed messages and the indexes those 
    /// messages had in the original vector of signed messages.
    ///  
    /// # Inputs:
    /// * `self`, a proof.
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `disclosed_messages` (OPTIONAL), a vector of octet string representing the messages 
    ///   disclosed to the Verifier.
    /// * `disclosed_indexes` (OPTIONAL), vector of usize, one per disclosed message: the index
    ///   that message had in the vector of signed messages. Indexes must be unique; if they are
    ///   not in ascending order, indexes and messages are sorted together.
    ///
    /// Returns [`Error::PoKSVerificationError`] if the numbers of disclosed messages and indexes
    /// differ or an index is repeated.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    ///
    /// # Output:
    /// a result: [`Ok`] or [`Error`].
    ///
    pub fn proof_verify(
        &self,
        pk: &BBSplusPublicKey,
        disclosed_messages: Option<&[Vec<u8>]>,
        disclosed_indexes: Option<&[usize]>,
        header: Option<&[u8]>,
        ph: Option<&[u8]>,
    ) -> Result<(), Error> {
        let proof = self.to_bbsplus_proof();
        let disclosed_messages = disclosed_messages.unwrap_or(&[]);
        let disclosed_indexes = disclosed_indexes.unwrap_or(&[]);
        // Messages and indexes come from the Prover presentation: a different count must be an
        // error, not a panic in the multi-exponentiation.
        if disclosed_messages.len() != disclosed_indexes.len() {
            return Err(Error::PoKSVerificationError(
                "number of disclosed messages different from number of disclosed indexes".to_owned(),
            ));
        }

        let disclosed_message_scalars =
            BBSplusMessage::messages_to_scalar::<CS>(disclosed_messages, CS::API_ID)?;

        // Sort the (index, message) pairs by index, so that each message keeps its index.
        let mut disclosed: Vec<(usize, BBSplusMessage)> = disclosed_indexes
            .iter()
            .copied()
            .zip(disclosed_message_scalars)
            .collect();
        disclosed.sort_by_key(|&(i, _)| i);
        if disclosed.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(Error::PoKSVerificationError("repeated disclosed index".to_owned()));
        }
        let (disclosed_indexes, disclosed_message_scalars): (Vec<usize>, Vec<BBSplusMessage>) =
            disclosed.into_iter().unzip();

        let U = proof.m_cap.len();
        let R = disclosed_indexes.len();

        let generators = Generators::create::<CS>(U + R + 1, Some(CS::API_ID));

        

        core_proof_verify::<CS>(
            pk,
            proof,
            &generators,
            header,
            ph,
            &disclosed_message_scalars,
            &disclosed_indexes,
            Some(CS::API_ID),
        )
    }

    /// Converts the `PoKSignature` to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bbsplus_proof().to_bytes()
    }

    /// Creates a `PoKSignature` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusPoKSignature::from_bytes(bytes)?))
    }

    /// Converts the `PoKSignature` to a `BBSplusPoKSignature`.
    pub fn to_bbsplus_proof(&self) -> &BBSplusPoKSignature {
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-coreproofgen
///
/// # Description
/// This operation computes a zero-knowledge proof-of-knowledge of a signature, while optionally
/// selectively disclosing from the original set of signed messages. 
/// The Prover may also supply a presentation header (ph).
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `signature` (REQUIRED), a [`BBSplusSignature`].
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `ph` (OPTIONAL), an octet string containing the presentation header.
/// * `messages` (OPTIONAL), a vector of scalars ([`BBSplusMessage`]) representing the signed messages.
/// * `disclosed_indexes` (OPTIONAL), vector of usize in ascending order. Indexes of disclosed messages.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a PoK of a Signature [`BBSplusPoKSignature`] or [`Error`].
///
// Same inputs, in the same order, as the draft procedure it implements.
#[allow(clippy::too_many_arguments)]
fn core_proof_gen<CS>(
    pk: &BBSplusPublicKey,
    signature: &BBSplusSignature,
    generators: &Generators,
    messages: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    header: Option<&[u8]>,
    ph: Option<&[u8]>,
    api_id: Option<&[u8]>,
    _seed: &[u8],
    _dst: &[u8],
) -> Result<BBSplusPoKSignature, Error>
where
    CS: BbsCiphersuite,
{
    let L = messages.len();
    if L > generators.values.len() - 1 {
        return Err(Error::NotEnoughGenerators);
    }

    let init_res = proof_init::<CS>(
        pk,
        signature,
        generators,
        header,
        messages,
        disclosed_indexes,
        api_id,
        _seed,
        _dst,
    )?;

    let challenge = proof_challenge_calculate::<CS>(
        &init_res,
        ph,
        api_id,
    )?;

    let proof = proof_finalize(
        &init_res,
        challenge
    )?;

    Ok(proof)
}

///https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-proof-initialization-result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ProofInitRes {
    pub Abar: G1Projective,
    pub Bbar: G1Projective,
    pub D: G1Projective,
    pub T1: G1Projective,
    pub T2: G1Projective,
    pub domain: Scalar,
    pub L: usize,
    pub disclosed_indexes: Vec<usize>,
    pub disclosed_messages: Vec<BBSplusMessage>,
    pub undisclosed_messages: Option<Vec<BBSplusMessage>>,
    pub e: Option<Scalar>,
    pub random_scalars: Option<Vec<Scalar>>,
}

pub(super) fn validate_init_res(init_res: &ProofInitRes) -> Result<(), Error> {

    if init_res.disclosed_messages.len() !=  init_res.disclosed_indexes.len(){
        return Err(Error::ProofGenError("Number of disclosed indexes different \
        from number of disclosed messages".to_owned()));
    }

    if let Some(invalid_index) = init_res.disclosed_indexes.iter().find(
        |&&i| i > init_res.L - 1
    ) {
        return Err(Error::ProofGenError(format!(
            "Invalid disclosed index: {}",
            invalid_index
        )));
    }

    match (&init_res.undisclosed_messages, &init_res.random_scalars) {
        (Some(undisclosed_messages), Some(random_scalars)) => {
            if random_scalars.len()  !=  undisclosed_messages.len() + 5 {
                return Err(Error::ProofGenError("Number of random scalars different \
                        from number of undisclosed messages".to_owned()));
            }
        },
        (None, None) => (),
        _ => return Err(Error::ProofGenError("Both undisclosed messages and \
                       random scalars must be present".to_owned())),
    }

    Ok(())
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-proof-initialization
///
/// # Description
/// This operation initializes the proof and returns one of the inputs passed to the challenge 
/// calculation operation ([`proof_challenge_calculate`]), during the [`core_proof_gen`] operation. 
/// The inputted messages MUST be supplied to this operation in the same order they had when
/// inputted to the `core_sign` operation
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `signature` (REQUIRED), a [`BBSplusSignature`].
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `messages` (OPTIONAL), a vector of scalars ([`BBSplusMessage`]).
/// * `disclosed_indexes` (OPTIONAL), vector of usize in ascending order. 
///   Indexes of undisclosed messages.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a [`ProofInitRes`] or [`Error`].
///
// Same inputs, in the same order, as the draft procedure it implements.
#[allow(clippy::too_many_arguments)]
pub(super) fn proof_init<CS>(
    pk: &BBSplusPublicKey,
    signature: &BBSplusSignature,
    generators: &Generators,
    header: Option<&[u8]>,
    messages: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    api_id: Option<&[u8]>,
    _seed: &[u8],
    _dst: &[u8],
) -> Result<ProofInitRes, Error>
where
    CS: BbsCiphersuite,
{
    let mut disclosed_indexes = disclosed_indexes.to_vec();
    disclosed_indexes.sort();
    disclosed_indexes.dedup();

    let U = messages
            .len()
            .checked_sub(disclosed_indexes.len())
            .ok_or_else(|| Error::ProofGenError("R > L".to_owned()))?;

    #[cfg(not(test))]
    let random_scalars = calculate_random_scalars(5 + U);

    #[cfg(test)]
    let random_scalars = seeded_random_scalars::<CS>(5 + U, _seed, _dst);

    proof_init_with_scalars::<CS>(
        pk,
        signature,
        generators,
        header,
        messages,
        &disclosed_indexes,
        api_id,
        random_scalars,
    )
}

/// Same as [`proof_init`], but the `5 + U` random scalars
/// `(r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU)` are supplied by the caller.
///
/// Needed when the random scalars must be drawn together with other values in a
/// single `calculate_random_scalars` call (e.g. the committed disclosure extension of
/// draft-irtf-cfrg-bbs-blind-signatures-05 §4.3.4, which draws `5 + U + 2*N` scalars).
// Same inputs, in the same order, as the draft procedure it implements.
#[allow(clippy::too_many_arguments)]
pub(super) fn proof_init_with_scalars<CS>(
    pk: &BBSplusPublicKey,
    signature: &BBSplusSignature,
    generators: &Generators,
    header: Option<&[u8]>,
    messages: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    api_id: Option<&[u8]>,
    random_scalars: Vec<Scalar>,
) -> Result<ProofInitRes, Error>
where
    CS: BbsCiphersuite,
{
    let L = messages.len();

    let mut disclosed_indexes = disclosed_indexes.to_vec();
    disclosed_indexes.sort();
    disclosed_indexes.dedup();

    let R = disclosed_indexes.len();

    let U = L
            .checked_sub(R)
            .ok_or_else(|| Error::ProofGenError("R > L".to_owned()))?;

    if let Some(invalid_index) = disclosed_indexes.iter().find(|&&i| i >= L) {
        return Err(Error::ProofGenError(format!(
            "Invalid disclosed index: {}",
            invalid_index
        )));
    }

    if random_scalars.len() != 5 + U {
        return Err(Error::ProofGenError(
            "Number of random scalars different from 5 + U".to_owned(),
        ));
    }

    let undisclosed_indexes: Vec<usize> = get_remaining_indexes(L, &disclosed_indexes);

    let disclosed_messages = get_messages(messages, &disclosed_indexes);
    let undisclosed_messages = get_messages(messages, &undisclosed_indexes);
    let undisclosed_generators = get_generators_from_indexes(generators, &undisclosed_indexes);

    let r1 = random_scalars[0];
    let r2 = random_scalars[1];
    let e_tilde = random_scalars[2];
    let r1_tilde = random_scalars[3];
    let r3_tilde = random_scalars[4];
    let m_tilde = &random_scalars[5..(5 + U)];

    let domain = calculate_domain::<CS>(pk, generators, header, api_id)?;

    let mut gens = Vec::with_capacity(generators.values.len() + 1);
    gens.push(generators.g1_base_point);
    gens.extend(generators.values.clone());

    let mut msg = Vec::with_capacity(messages.len() + 2);
    msg.push(Scalar::ONE);
    msg.push(domain);
    msg.extend(messages.iter().map(|m| m.value));

    let B = multi_exponentiation_g1(&gens, &msg);

    let D = B * r2;
    let Abar = signature.A * (r1 * r2);

    let Bbar = multi_exponentiation_g1([D, Abar].as_ref(), [r1,-signature.e].as_ref());
    let T1 = multi_exponentiation_g1([Abar, D].as_ref(), [e_tilde, r1_tilde].as_ref());

    let mut t2gens = Vec::with_capacity(undisclosed_generators.len() + 1);
    t2gens.push(D);
    t2gens.extend(undisclosed_generators);

    let mut t2scalars = Vec::with_capacity(m_tilde.len() + 1);
    t2scalars.push(r3_tilde);
    t2scalars.extend(m_tilde);

    let T2 = multi_exponentiation_g1(&t2gens, &t2scalars);

    Ok(ProofInitRes {
        Abar,
        Bbar,
        D,
        T1,
        T2,
        domain,
        L,
        disclosed_indexes,
        disclosed_messages,
        undisclosed_messages: Some(undisclosed_messages),
        e: Some(signature.e),
        random_scalars: Some(random_scalars),
    })
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-challenge-calculation
///
/// # Description
/// This operation calculates the challenge scalar value, used during the [`core_proof_gen`]
/// and [`core_proof_verify`], as part of the Fiat-Shamir heuristic, for making the proof protocol
/// non-interactive (in a interactive setting, the challenge would be a random value
/// supplied by the Verifier).
///
/// # Inputs:
/// * `init_res` (REQUIRED), [`ProofInitRes`] returned after initializing the proof generation
///   or verification operations.
/// * `ph` (OPTIONAL), an octet string containing the presentation header.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a challenge ([`Scalar`]) or [`Error`].
///
fn proof_challenge_calculate<CS>(
    init_res: &ProofInitRes,
    ph: Option<&[u8]>,
    api_id: Option<&[u8]>,
) -> Result<Scalar, Error>
where
    CS: BbsCiphersuite,
{
    let api_id = api_id.unwrap_or(b"");
    let challenge_dst = [api_id, CS::H2S].concat();

    let ph = ph.unwrap_or(b"");

    let mut c_arr = proof_challenge_octets(init_res, &[])?;

    let ph_i2osp = i2osp::<8>(ph.len());

    c_arr.extend_from_slice(&ph_i2osp);
    c_arr.extend_from_slice(ph);

    hash_to_scalar::<CS>(&c_arr, &challenge_dst)
}

/// Serialization of `(R, i1, msg_i1, ..., iR, msg_iR, Abar, Bbar, D, T1, T2, extra..., domain)`,
/// the common prefix of the challenge input, shared with the blind (committed disclosure)
/// and pseudonym challenge calculations.
///
/// `extra_points` are serialized between `T2` and `domain`: empty for BBS and Blind BBS,
/// `(pseudonym, Ut)` for the pseudonym proof
/// (draft-irtf-cfrg-bbs-per-verifier-linkability-05 §9.1, procedure step 1).
fn proof_challenge_octets(
    init_res: &ProofInitRes,
    extra_points: &[G1Projective],
) -> Result<Vec<u8>, Error> {
    validate_init_res(init_res)?;

    let R = init_res.disclosed_indexes.len();

    let mut c_arr: Vec<u8> = Vec::new();
    c_arr.extend_from_slice(&i2osp::<8>(R));
    for (i, m) in core::iter::zip(
        &init_res.disclosed_indexes,
        &init_res.disclosed_messages
    ) {
        c_arr.extend_from_slice(&i2osp::<8>(*i));
        c_arr.extend_from_slice(&m.value.to_bytes_be());
    }
    c_arr.extend_from_slice(&init_res.Abar.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.Bbar.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.D.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.T1.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.T2.to_affine().to_compressed());
    for P in extra_points {
        c_arr.extend_from_slice(&P.to_affine().to_compressed());
    }
    c_arr.extend_from_slice(&init_res.domain.to_bytes_be());

    Ok(c_arr)
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-proof-finalization
///
/// # Description
/// This operation finalizes the proof calculation during the [`core_proof_gen`] operation and
/// returns the PoK [`BBSplusPoKSignature`].
///
/// # Inputs:
/// * `init_res` (REQUIRED), [`ProofInitRes`] returned after initializing object representing
///   the value returned after initializing the proof generation
///   or verification operations
/// * `challenge` (REQUIRED), a scalar value.
///
/// # Output:
/// a proof ([`BBSplusPoKSignature`]) or [`Error`].
///
pub(super) fn proof_finalize(
    init_res: &ProofInitRes,
    challenge: Scalar
) -> Result<BBSplusPoKSignature, Error> {

    validate_init_res(init_res)?;

    let random_scalars = init_res.random_scalars.as_ref()
            .ok_or_else(|| Error::ProofGenError("Missing random scalars in proof_finalize".to_owned()))?;

    let undisclosed_messages=init_res.undisclosed_messages.as_ref()
            .ok_or_else(|| Error::ProofGenError("Missing random scalars in proof_finalize".to_owned()))?;

    let e = init_res.e
            .ok_or_else(|| Error::ProofGenError("Missing e in proof_finalize".to_owned()))?;

    let U = undisclosed_messages.len();

    let r1 = random_scalars[0];
    let r2 = random_scalars[1];
    let e_tilde = random_scalars[2];
    let r1_tilde = random_scalars[3];
    let r3_tilde = random_scalars[4];
    let m_tilde = &random_scalars[5..(5 + U)];

    let r3 = Option::<Scalar>::from(r2.invert())
        .ok_or_else(|| Error::ProofGenError("Invert scalar failed".to_owned()))?;

    let e_cap = e_tilde + e * challenge;

    let r1_cap = r1_tilde - r1 * challenge;
    let r3_cap = r3_tilde - r3 * challenge;
    let mut m_cap: Vec<Scalar> = Vec::new();

    for j in 0..U {
        let m_cap_j = m_tilde[j] + undisclosed_messages[j].value * challenge;
        m_cap.push(m_cap_j);
    }

    Ok(BBSplusPoKSignature {
        Abar: init_res.Abar,
        Bbar: init_res.Bbar,
        D: init_res.D,
        e_cap,
        r1_cap,
        r3_cap,
        m_cap,
        challenge,
    })
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-coreproofverify
///
/// # Description
/// This operation checks that a proof is valid for a header,
/// vector of disclosed messages (disclosed_messages) along side their index corresponding
/// to their original position when signed (disclosed_indexes) and presentation
/// header (ph) against a public key (PK).
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `proof` (REQUIRED), a [`BBSplusPoKSignature`].
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `ph` (OPTIONAL), an octet string containing the presentation header.
/// * `disclosed_messages` (OPTIONAL), a vector of scalars ([`BBSplusMessage`])
///   representing the messages disclosed to the Verifier.
/// * `disclosed_indexes` (OPTIONAL), vector of unsigned integers in ascending order.
///   Indexes of disclosed messages.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a result: [`Ok`] or [`Error`].
///
// Same inputs, in the same order, as the draft procedure it implements.
#[allow(clippy::too_many_arguments)]
fn core_proof_verify<CS>(
    pk: &BBSplusPublicKey,
    proof: &BBSplusPoKSignature,
    generators: &Generators,
    header: Option<&[u8]>,
    ph: Option<&[u8]>,
    disclosed_messages: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    api_id: Option<&[u8]>,
) -> Result<(), Error>
where
    CS: BbsCiphersuite,
{
    let init_res = proof_verify_init::<CS>(
        pk,
        proof,
        generators,
        header,
        disclosed_messages,
        disclosed_indexes,
        api_id,
    )?;

    let challenge = proof_challenge_calculate::<CS>(
        &init_res,
        ph,
        api_id,
    )?;

    if proof.challenge != challenge {
        return Err(Error::PoKSVerificationError("invalid challenge".to_owned()));
    }

    verify_proof_pairing(pk, proof)
}

/// Final pairing check of the proof verification: `e(Abar, W) * e(Bbar, -BP2) == Identity_GT`.
pub(super) fn verify_proof_pairing(pk: &BBSplusPublicKey, proof: &BBSplusPoKSignature) -> Result<(), Error> {
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

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-proof-verification-initiali
///
/// # Description
/// This operation initializes the proof verification operation and returns part of the input that
/// will be passed to the challenge calculation operation ([`proof_challenge_calculate`]),
/// during the [`core_proof_verify`] operation.
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `proof` (REQUIRED), a [`BBSplusPoKSignature`].
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `disclosed_messages` (REQUIRED), a vector of scalars ([`BBSplusMessage`])
///   representing the messages disclosed to the Verifier.
///   It could be empty.
/// * `disclosed_indexes` (REQUIRED), vector of unsigned integers in ascending order.
///   Indexes of disclosed messages. It could be empty.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a [`ProofInitRes`] or [`Error`].
///
pub(super) fn proof_verify_init<CS>(
    pk: &BBSplusPublicKey,
    proof: &BBSplusPoKSignature,
    generators: &Generators,
    header: Option<&[u8]>,
    disclosed_messages: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    api_id: Option<&[u8]>,
) -> Result<ProofInitRes, Error>
where
    CS: BbsCiphersuite,
{
    // draft-irtf-cfrg-bbs-signatures-15 §4.2.5.5 octets_to_proof step 7 and §4.2.5.6
    // octets_to_pubkey step 4. `from_bytes` already enforces them, but a proof or a key can
    // also come from serde (whose point decoding accepts the identity): repeat them here so
    // every verification path (BBS, Blind BBS, pseudonyms) applies them. With
    // Abar = Bbar = Identity_G1 the pairing check is trivially satisfied and the rest of the
    // proof can be forged for any disclosed messages without a signature.
    if bool::from(proof.Abar.is_identity())
        || bool::from(proof.Bbar.is_identity())
        || bool::from(proof.D.is_identity())
    {
        return Err(Error::InvalidProofOfKnowledgeSignature);
    }
    if bool::from(pk.0.is_identity()) {
        return Err(Error::KeyDeserializationError);
    }

    let U = proof.m_cap.len();
    let R = disclosed_indexes.len();
    if disclosed_messages.len() != R {
        return Err(Error::PoKSVerificationError(
            "number of disclosed messages different from number of disclosed indexes".to_owned(),
        ));
    }

    let L = U + R;

    for &i in disclosed_indexes {
        if i > L - 1 {
            return Err(Error::PoKSVerificationError(
                "Invalid disclosed indexes".to_owned(),
            ));
        }
    }

    if generators.values.len() != L + 1 {
        return Err(Error::NotEnoughGenerators);
    }

    let undisclosed_indexes = get_remaining_indexes(L, disclosed_indexes);

    let domain = calculate_domain::<CS>(pk, generators, header, api_id)?;

    let T1 = multi_exponentiation_g1(
        [proof.Bbar, proof.Abar, proof.D].as_ref(),
        [proof.challenge,proof.e_cap, proof.r1_cap].as_ref()
    );

    let disclosed_generators = get_generators_from_indexes(generators, disclosed_indexes);

    let mut Bvgens = Vec::with_capacity(disclosed_generators.len() + 1);
    Bvgens.push(generators.g1_base_point);
    Bvgens.push(generators.values[0]);
    Bvgens.extend(disclosed_generators);

    let mut Bvscalars = Vec::with_capacity(disclosed_messages.len() + 2);
    Bvscalars.push(Scalar::ONE);
    Bvscalars.push(domain);
    Bvscalars.extend(disclosed_messages.iter().map(|m| m.value));

    let Bv = multi_exponentiation_g1(&Bvgens, &Bvscalars);

    let undisclosed_generators = get_generators_from_indexes(
        generators,
        &undisclosed_indexes
    );

    let mut T2gens = Vec::with_capacity(undisclosed_generators.len() + 1);
    T2gens.push(Bv);
    T2gens.push(proof.D);
    T2gens.extend(undisclosed_generators);

    let mut T2scalars = Vec::with_capacity(disclosed_messages.len() + 2);
    T2scalars.push(proof.challenge);
    T2scalars.push(proof.r3_cap);
    T2scalars.extend(&proof.m_cap);

    let T2 = multi_exponentiation_g1(&T2gens, &T2scalars);

    Ok(ProofInitRes {
        Abar: proof.Abar,
        Bbar: proof.Bbar,
        D: proof.D,
        T1,
        T2,
        domain,
        L,
        disclosed_indexes: disclosed_indexes.to_vec(),
        disclosed_messages: disclosed_messages.to_vec(),
        undisclosed_messages: None,
        e: None,
        random_scalars: None,
    })
}

/// Represents a Commitment proof
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusZKPoK {
    pub(crate) s_cap: Scalar,
    pub(crate) m_cap: Vec<Scalar>,
    pub(crate) challenge: Scalar,
}

impl BBSplusZKPoK {
    /// Creates a new `BBSplusZKPoK` instance.
    ///
    /// # Arguments
    ///
    /// * `s_cap` - A scalar value representing the s_cap.
    /// * `m_cap` - A vector of scalar values representing the m_cap.
    /// * `challenge` - A scalar value representing the challenge.
    pub fn new(s_cap: Scalar, m_cap: Vec<Scalar>, challenge: Scalar) -> Self {
        Self {
            s_cap,
            m_cap,
            challenge,
        }
    }

    /// Converts the `BBSplusZKPoK` to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.s_cap.to_bytes_be());
        self.m_cap
            .iter()
            .for_each(|s| bytes.extend_from_slice(&s.to_bytes_be()));
        bytes.extend_from_slice(&self.challenge.to_bytes_be());
        bytes
    }

    /// Creates a `BBSplusZKPoK` from a byte slice.
    /// 
    /// # Arguments
    /// 
    /// * `bytes` - A byte slice representing the `BBSplusZKPoK`.
    /// 
    /// # Output
    /// * A Result containing the `BBSplusZKPoK` or an Error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // s^ and challenge are always present, followed by one m^ per committed message
        if bytes.len() < 2 * Scalar::BYTES || !bytes.len().is_multiple_of(Scalar::BYTES) {
            return Err(Error::InvalidCommitmentProof);
        }

        // draft-irtf-cfrg-bbs-blind-signatures-05, octets_to_commitment_with_proof step 13:
        // if s_j = 0 or if s_j >= r, return INVALID. from_bytes_be only rejects s_j >= r.
        let parse_scalar = |chunk: &[u8]| -> Result<Scalar, Error> {
            let s = Scalar::from_bytes_be(chunk).map_err(|_| Error::InvalidCommitmentProof)?;
            if s == Scalar::ZERO {
                return Err(Error::InvalidCommitmentProof);
            }
            Ok(s)
        };

        let s_cap = parse_scalar(&bytes[0..Scalar::BYTES])?;

        let mut m_cap: Vec<Scalar> = Vec::new();

        for chunk in bytes[Scalar::BYTES..].as_chunks::<{ Scalar::BYTES }>().0 {
            m_cap.push(parse_scalar(chunk)?);
        }

        //at least the challenge should be present (even if all attributes are disclosed)
        let challenge = m_cap.pop().ok_or(Error::InvalidCommitmentProof)?;

        Ok(Self {
            s_cap,
            m_cap,
            challenge,
        })
    }
}

#[cfg(test)]
mod tests;
