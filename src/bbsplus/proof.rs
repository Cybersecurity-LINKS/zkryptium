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

use alloc::{borrow::ToOwned, vec::Vec};
use super::{
    ciphersuites::BbsCiphersuite, commitment::BlindFactor, generators::Generators,
    keys::BBSplusPublicKey, signature::BBSplusSignature,
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
use elliptic_curve::{group::Curve, hash2curve::ExpandMsg, Group};
use serde::{Deserialize, Serialize};

#[cfg(not(test))]
use crate::utils::util::bbsplus_utils::calculate_random_scalars;
#[cfg(test)]
use crate::utils::util::bbsplus_utils::seeded_random_scalars;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusPoKSignature {
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
        self.m_cap
            .iter()
            .for_each(|v| bytes.extend_from_slice(&v.to_bytes_be()));
        bytes.extend_from_slice(&self.challenge.to_bytes_be());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let Abar = parse_g1_projective(&bytes[0..48])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
        let Bbar = parse_g1_projective(&bytes[48..96])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
        let D = parse_g1_projective(&bytes[96..144])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;

        let e_cap = Scalar::from_bytes_be(&bytes[144..176])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
        let r1_cap = Scalar::from_bytes_be(&bytes[176..208])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
        let r3_cap = Scalar::from_bytes_be(&bytes[208..240])
            .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;

        let mut m_cap: Vec<Scalar> = Vec::new();

        for chunk in bytes[240..].chunks_exact(32) {
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

impl<CS: BbsCiphersuite> PoKSignature<BBSplus<CS>> {
    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-proof-generation-proofgen
    ///
    /// # Description
    /// This operation creates BBS proof, which is a zero-knowledge, proof-of-knowledge of a BBS signature, while optionally disclosing any subset of the signed messages.
    ///
    /// # Inputs:
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `signature` (REQUIRED), an octet string.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `messages` (OPTIONAL), a vector of octet strings representing the signed messages.
    /// * `disclosed_indexes` (OPTIONAL), vector of unsigned integers in ascending order. Indexes of disclosed messages.
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
    ) -> Result<Self, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
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
            &CS::SEED_MOCKED_SCALAR,
            &CS::MOCKED_SCALAR_DST,
        )?;

        Ok(Self::BBSplus(proof))
    }

    /// https://datatracker.ietf.org/doc/html/draft-kalos-bbs-blind-signatures-01#name-proof-generation
    ///
    /// # Description
    /// This operation creates a BBS proof, which is a zero-knowledge, proof-of-knowledge, of a BBS signature, while optionally disclosing any subset of the signed messages. Note that in contrast to the [`Self::proof_gen`] operation, this operation accepts 2 different lists of messages and disclosed indexes, one for the messages known to the Signer (messages) and the corresponding disclosed indexes (disclosed_indexes) and one for the messages committed by the Prover (committed_messages) and the corresponding disclosed indexes (disclosed_commitment_indexes).
    /// To Verify a proof however, the Verifier expects only one list of messages and one list of disclosed indexes. This is done to avoid revealing which of the disclosed messages where committed by the Prover and which are known to the Verifier.
    ///
    /// # Inputs:
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `signature` (REQUIRED), an octet string.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `messages` (OPTIONAL), a vector of octet strings messages supplied by the Signer.  If not supplied, it defaults to the empty array.
    /// * `committed_messages` (OPTIONAL), a vector of octet strings messages committed by the Prover.
    /// * `disclosed_indexes` (OPTIONAL), vector of unsigned integers in ascending order. Indexes of disclosed messages.
    /// * `disclosed_commitment_indexes` (OPTIONAL), vector of unsigned integers in ascending order. Indexes of disclosed committed messages.
    /// * `secret_prover_blind` (OPTIONAL), a scalar value ([`BlindFactor`]).
    /// * `signer_blind` (OPTIONAL), a scalar value ([`BlindFactor`]).
    ///
    /// # Output:
    /// [`PoKSignature::BBSplus`] or [`Error`]: a PoK of a Signature, a vector of octet strings representing all the disclosed messages and their indexes.
    ///
    pub fn blind_proof_gen(
        pk: &BBSplusPublicKey,
        signature: &[u8],
        header: Option<&[u8]>,
        ph: Option<&[u8]>,
        messages: Option<&[Vec<u8>]>,
        committed_messages: Option<&[Vec<u8>]>,
        disclosed_indexes: Option<&[usize]>,
        disclosed_commitment_indexes: Option<&[usize]>,
        secret_prover_blind: Option<&BlindFactor>,
        signer_blind: Option<&BlindFactor>,
    ) -> Result<Self, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let signature = BBSplusSignature::from_bytes(
            signature.try_into().map_err(|_| Error::InvalidSignature)?,
        )?;
        let api_id = CS::API_ID_BLIND;
        let messages = messages.unwrap_or(&[]);
        let committed_messages = committed_messages.unwrap_or(&[]);
        let L = messages.len();
        let M = committed_messages.len();

        let disclosed_indexes = disclosed_indexes.unwrap_or(&[]);
        let disclosed_commitment_indexes = disclosed_commitment_indexes.unwrap_or(&[]);

        if disclosed_indexes.len() > L {
            return Err(Error::BlindProofGenError(
                "number of disclosed indexes is grater than the number of messages".to_owned(),
            ));
        } else if disclosed_indexes.iter().any(|&i| i >= L) {
            return Err(Error::BlindProofGenError(
                "disclosed index out of range".to_owned(),
            ));
        } else if disclosed_commitment_indexes.len() > M {
            return Err(Error::BlindProofGenError("number of commitment disclosed indexes is grater than the number of committed messages".to_owned()));
        } else if disclosed_commitment_indexes.iter().any(|&i| i >= M) {
            return Err(Error::BlindProofGenError(
                "commitment disclosed index out of range".to_owned(),
            ));
        }

        let generators = Generators::create::<CS>(L + 1, Some(api_id));
        let blind_generators = Generators::create::<CS>(M + 1, Some(&[b"BLIND_", api_id].concat()));

        let message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, api_id)?;
        let blind_factor = BBSplusMessage::new(
            secret_prover_blind.map_or(Scalar::ZERO, |b| b.0)
                + signer_blind.map_or(Scalar::ZERO, |b| b.0),
        );
        let committed_message_scalars =
            BBSplusMessage::messages_to_scalar::<CS>(committed_messages, api_id)?;

        let indexes = disclosed_indexes
            .iter()
            .copied()
            .chain(disclosed_commitment_indexes.iter().map(|&j| j + L + 1))
            .collect::<Vec<_>>();

        let tmp_messages = [
            &*message_scalars,
            core::slice::from_ref(&blind_factor),
            &*committed_message_scalars,
        ]
        .concat();

        let proof = core_proof_gen::<CS>(
            pk,
            &signature,
            &generators.append(blind_generators),
            &tmp_messages,
            &indexes,
            header,
            ph,
            Some(api_id),
            CS::SEED_MOCKED_SCALAR,
            &CS::BLIND_PROOF_DST,
        )?;

        Ok(Self::BBSplus(proof))
    }

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-proof-verification-proofver
    ///
    /// # Description
    /// The ProofVerify operation validates a BBS proof, given the Signer's public key (PK), a header and presentation header values, the disclosed messages and the indexes those messages had in the original vector of signed messages.
    /// Inside is using the [`BbsCiphersuite::API_ID`] api_id.
    ///  
    /// # Inputs:
    /// * `self`, a proof.
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `disclosed_messages` (OPTIONAL), a vector of octet string representing the messages disclosed to the Verifier.
    /// * `disclosed_indexes` (OPTIONAL), vector of usize in ascending order. Indexes of disclosed messages.
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
    ) -> Result<(), Error>
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

        let disclosed_message_scalars =
            BBSplusMessage::messages_to_scalar::<CS>(disclosed_messages, CS::API_ID)?;

        let generators = Generators::create::<CS>(U + R + 1, Some(CS::API_ID));

        let result = core_proof_verify::<CS>(
            pk,
            proof,
            &generators,
            header,
            ph,
            &disclosed_message_scalars,
            &disclosed_indexes,
            Some(CS::API_ID),
        );

        result
    }

    /// https://datatracker.ietf.org/doc/html/draft-kalos-bbs-blind-signatures-01#name-proof-verification
    ///
    /// # Description
    /// The ProofVerify operation validates a BBS proof, given the Signer's public key (PK), a
    /// header and presentation header values, two arrays of disclosed messages (the ones known to
    /// the Signer and the ones committed by the prover) and two corresponding arrays of indexes
    /// those messages had in the original vectors of signed messages. In addition, the
    /// BlindProofVerify operation defined in this section accepts the integer L, representing the
    /// total number of signed messages known by the Signer.
    ///
    /// # Inputs:
    /// * `self`, a proof.
    /// * `pk` (REQUIRED), the Signer public key.
    /// * `header` (OPTIONAL), an octet string containing context and application.
    /// * `ph` (OPTIONAL), an octet string containing the presentation header.
    /// * `L` (OPTIONAL), an integer, representing the total number of Signer known messages if not supplied it defaults to 0.
    /// * `disclosed_messages` (OPTIONAL), a vector of octet string representing the messages disclosed to the Verifier.
    /// * `disclosed_committed_messages` (OPTIONAL), a vector of octet string representing the committed messages disclosed to the Verifier.
    /// * `disclosed_indexes` (OPTIONAL), vector of usize in ascending order. Indexes of disclosed messages.
    /// * `disclosed_commitment_indexes` (OPTIONAL), vector of usize in ascending order. Indexes of disclosed committed messages.
    ///
    /// # Output:
    /// a result: [`Ok`] or [`Error`].
    ///
    pub fn blind_proof_verify(
        &self,
        pk: &BBSplusPublicKey,
        header: Option<&[u8]>,
        ph: Option<&[u8]>,
        L: Option<usize>,
        disclosed_messages: Option<&[Vec<u8>]>,
        disclosed_committed_messages: Option<&[Vec<u8>]>,
        disclosed_indexes: Option<&[usize]>,
        disclosed_commitment_indexes: Option<&[usize]>,
    ) -> Result<(), Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let proof = self.to_bbsplus_proof();
        let L = L.unwrap_or(0);
        let disclosed_messages = disclosed_messages.unwrap_or(&[]);
        let disclosed_committed_messages = disclosed_committed_messages.unwrap_or(&[]);
        let mut disclosed_indexes = disclosed_indexes.unwrap_or(&[]).to_vec();
        disclosed_indexes.sort();
        disclosed_indexes.dedup();
        let mut disclosed_commitment_indexes = disclosed_commitment_indexes.unwrap_or(&[]).to_vec();
        disclosed_commitment_indexes.sort();
        disclosed_commitment_indexes.dedup();

        let api_id = CS::API_ID_BLIND;

        let U = proof.m_cap.len();
        let M = disclosed_indexes.len() + disclosed_commitment_indexes.len() + U - 1 - L;

        let generators = Generators::create::<CS>(L + 1, Some(api_id));
        let blind_generators = Generators::create::<CS>(M + 1, Some(&[b"BLIND_", api_id].concat()));

        let message_scalars = [
            BBSplusMessage::messages_to_scalar::<CS>(disclosed_messages, api_id)?,
            BBSplusMessage::messages_to_scalar::<CS>(disclosed_committed_messages, api_id)?,
        ]
        .concat();

        let indexes = disclosed_indexes
            .iter()
            .copied()
            .chain(disclosed_commitment_indexes.iter().map(|j| j + L + 1))
            .collect::<Vec<_>>();

        core_proof_verify::<CS>(
            pk,
            proof,
            &generators.append(blind_generators),
            header,
            ph,
            &message_scalars,
            &indexes,
            Some(api_id),
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bbsplus_proof().to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusPoKSignature::from_bytes(bytes)?))
    }

    pub fn to_bbsplus_proof(&self) -> &BBSplusPoKSignature {
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-coreproofgen
///
/// # Description
/// This operation computes a zero-knowledge proof-of-knowledge of a signature, while optionally selectively disclosing from the original set of signed messages. The Prover may also supply a presentation header (ph).
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
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let L = messages.len();
    if L > generators.values.len() - 1 {
        return Err(Error::NotEnoughGenerators);
    }

    let mut disclosed_indexes = disclosed_indexes.to_vec();
    disclosed_indexes.sort();
    disclosed_indexes.dedup();

    let R = disclosed_indexes.len();

    let U = L
        .checked_sub(R)
        .ok_or_else(|| Error::ProofGenError("R > L".to_owned()))?;

    if let Some(invalid_index) = disclosed_indexes.iter().find(|&&i| i > L - 1) {
        return Err(Error::ProofGenError(format!(
            "Invalid disclosed index: {}",
            invalid_index
        )));
    }

    let undisclosed_indexes: Vec<usize> = get_remaining_indexes(L, &disclosed_indexes);

    let disclosed_messages = get_messages(messages, &disclosed_indexes);
    let undisclosed_messages = get_messages(messages, &undisclosed_indexes);

    #[cfg(not(test))]
    let random_scalars = calculate_random_scalars(5 + U);

    #[cfg(test)]
    let random_scalars = seeded_random_scalars::<CS>(5 + U, _seed, _dst);

    let init_res = proof_init::<CS>(
        pk,
        signature,
        generators,
        &random_scalars,
        header,
        messages,
        &undisclosed_indexes,
        api_id,
    )?;

    let challenge = proof_challenge_calculate::<CS>(
        &init_res,
        &disclosed_indexes,
        &disclosed_messages,
        ph,
        api_id,
    )?;

    let proof = proof_finalize(
        &init_res,
        challenge,
        signature.e,
        &random_scalars,
        &undisclosed_messages,
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
    domain: Scalar,
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-proof-initialization
///
/// # Description
/// This operation initializes the proof and returns one of the inputs passed to the challenge calculation operation ([`proof_challenge_calculate`]), during the [`core_proof_gen`] operation.
/// The inputted messages MUST be supplied to this operation in the same order they had when inputted to the `core_sign` operation
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `signature` (REQUIRED), a [`BBSplusSignature`].
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `random_scalars` (REQUIRED), vector of scalar values.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `messages` (OPTIONAL), a vector of scalars ([`BBSplusMessage`]).
/// * `undisclosed_indexes` (OPTIONAL), vector of usize in ascending order. Indexes of undisclosed messages.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a [`ProofInitResult`] or [`Error`].
///
fn proof_init<CS>(
    pk: &BBSplusPublicKey,
    signature: &BBSplusSignature,
    generators: &Generators,
    random_scalars: &[Scalar],
    header: Option<&[u8]>,
    messages: &[BBSplusMessage],
    undisclosed_indexes: &[usize],
    api_id: Option<&[u8]>,
) -> Result<ProofInitResult, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let L = messages.len();
    let U = undisclosed_indexes.len();

    if random_scalars.len() != 5 + U {
        return Err(Error::ProofGenError("Random scalars not valid".to_owned()));
    }

    if generators.values.len() != L + 1 {
        return Err(Error::NotEnoughGenerators);
    }

    let Q1 = generators.values[0];
    let H_points = &generators.values[1..];

    let domain = calculate_domain::<CS>(pk, Q1, H_points, header, api_id)?;

    let mut B = generators.g1_base_point + Q1 * domain;
    for i in 0..L {
        B = B + H_points[i] * messages[i].value;
    }

    let r1 = random_scalars[0];
    let r2 = random_scalars[1];
    let e_tilde = random_scalars[2];
    let r1_tilde = random_scalars[3];
    let r3_tilde = random_scalars[4];
    let m_tilde = &random_scalars[5..(5 + U)];

    let D = B * r2;
    let Abar = signature.A * (r1 * r2);
    let Bbar = D * r1 - Abar * signature.e;

    let T1 = Abar * e_tilde + D * r1_tilde;
    let mut T2 = D * r3_tilde;

    for idx in 0..U {
        T2 = T2 + H_points[undisclosed_indexes[idx]] * m_tilde[idx];
    }

    Ok(ProofInitResult {
        Abar,
        Bbar,
        D,
        T1,
        T2,
        domain,
    })
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-challenge-calculation
///
/// # Description
/// This operation calculates the challenge scalar value, used during the [`core_proof_gen`] and [`core_proof_verify`], as part of the Fiat-Shamir heuristic, for making the proof protocol non-interactive (in a interactive setting, the challenge would be a random value supplied by the Verifier).
///
/// # Inputs:
/// * `init_res` (REQUIRED), [`ProofInitResult`] returned after initializing the proof generation or verification operations, consisting of 5 points of G1 and a scalar value, in that order.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `dsclosed_messages` (OPTIONAL), a vector of scalars ([`BBSplusMessage`]) representing the disclosed messages to the Verifier.
/// * `disclosed_indexes` (OPTIONAL), vector of usize in ascending order. Indexes of disclosed messages.
/// * `ph` (OPTIONAL), an octet string containing the presentation header.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a challenge ([`Scalar`]) or [`Error`].
///
fn proof_challenge_calculate<CS>(
    init_res: &ProofInitResult,
    disclosed_indexes: &[usize],
    disclosed_messages: &[BBSplusMessage],
    ph: Option<&[u8]>,
    api_id: Option<&[u8]>,
) -> Result<Scalar, Error>
where
    CS: BbsCiphersuite,
{
    let R = disclosed_indexes.len();

    if disclosed_messages.len() != R {
        return Err(Error::ProofGenError(
            "Number of disclosed indexes different from number of disclosed messages".to_owned(),
        ));
    }

    let api_id = api_id.unwrap_or(b"");
    let challenge_dst = [api_id, CS::H2S].concat();

    let ph = ph.unwrap_or(b"");

    let mut c_arr: Vec<u8> = Vec::new();
    c_arr.extend_from_slice(&i2osp::<8>(R));
    for (i, m) in core::iter::zip(disclosed_indexes, disclosed_messages) {
        c_arr.extend_from_slice(&i2osp::<8>(*i));
        c_arr.extend_from_slice(&m.value.to_bytes_be());
    }
    c_arr.extend_from_slice(&init_res.Abar.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.Bbar.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.D.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.T1.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.T2.to_affine().to_compressed());
    c_arr.extend_from_slice(&init_res.domain.to_bytes_be());

    let ph_i2osp = i2osp::<8>(ph.len());

    c_arr.extend_from_slice(&ph_i2osp);
    c_arr.extend_from_slice(ph);

    hash_to_scalar::<CS>(&c_arr, &challenge_dst)
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-proof-finalization
///
/// # Description
/// This operation finalizes the proof calculation during the [`core_proof_gen`] operation and returns the PoK [`BBSplusPoKSignature`].
///
/// # Inputs:
/// * `init_res` (REQUIRED), [`ProofInitResult`] returned after initializing the proof generation or verification operations, consisting of 5 points of G1 and a scalar value, in that order.
/// * `challenge` (REQUIRED), a scalar value.
/// * `e` (REQUIRED), a scalar value.
/// * `random_scalars` (REQUIRED), a vector of random scalars.
/// * `dsclosed_messages` (OPTIONAL), a vector of scalars ([`BBSplusMessage`]) representing the disclosed messages to the Verifier.
///
/// # Output:
/// a proof ([`BBSplusPoKSignature`]) or [`Error`].
///
fn proof_finalize(
    init_res: &ProofInitResult,
    challenge: Scalar,
    e: Scalar,
    random_scalars: &[Scalar],
    undisclosed_messages: &[BBSplusMessage],
) -> Result<BBSplusPoKSignature, Error> {
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

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-coreproofverify
///
/// # Description
/// This operation checks that a proof is valid for a header, vector of disclosed messages (disclosed_messages) along side their index corresponding to their original position when signed (disclosed_indexes) and presentation header (ph) against a public key (PK).
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `proof` (REQUIRED), a [`BBSplusPoKSignature`].
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `ph` (OPTIONAL), an octet string containing the presentation header.
/// * `disclosed_messages` (OPTIONAL), a vector of scalars ([`BBSplusMessage`]) representing the messages disclosed to the Verifier.
/// * `disclosed_indexes` (OPTIONAL), vector of unsigned integers in ascending order. Indexes of disclosed messages.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a result: [`Ok`] or [`Error`].
///
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
        disclosed_indexes,
        disclosed_messages,
        ph,
        api_id,
    )?;

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

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-proof-verification-initiali
///
/// # Description
/// This operation initializes the proof verification operation and returns part of the input that will be passed to the challenge calculation operation ([`proof_challenge_calculate`]), during the [`core_proof_verify`] operation.
///
/// # Inputs:
/// * `pk` (REQUIRED), the Signer public key.
/// * `proof` (REQUIRED), a [`BBSplusPoKSignature`].
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application.
/// * `disclosed_messages` (REQUIRED), a vector of scalars ([`BBSplusMessage`]) representing the messages disclosed to the Verifier. It could be empty.
/// * `disclosed_indexes` (REQUIRED), vector of unsigned integers in ascending order. Indexes of disclosed messages. It could be empty.
/// * `api_id` (OPTIONAL), an octet string.
///
/// # Output:
/// a [`ProofInitResult`] or [`Error`].
///
fn proof_verify_init<CS>(
    pk: &BBSplusPublicKey,
    proof: &BBSplusPoKSignature,
    generators: &Generators,
    header: Option<&[u8]>,
    disclosed_messages: &[BBSplusMessage],
    disclosed_indexes: &[usize],
    api_id: Option<&[u8]>,
) -> Result<ProofInitResult, Error>
where
    CS: BbsCiphersuite,
{
    let U = proof.m_cap.len();
    let R = disclosed_indexes.len();

    let L = U + R;

    for &i in disclosed_indexes {
        if i > L - 1 {
            return Err(Error::PoKSVerificationError(
                "Invalid disclosed indexes".to_owned(),
            ));
        }
    }

    if disclosed_messages.len() != R {
        return Err(Error::PoKSVerificationError(
            "len messages != len indexes".to_owned(),
        ));
    }

    if generators.values.len() != L + 1 {
        return Err(Error::NotEnoughGenerators);
    }

    let Q1 = generators.values[0];
    let H_points = &generators.values[1..];

    let undisclosed_indexes = get_remaining_indexes(L, disclosed_indexes);

    let domain = calculate_domain::<CS>(pk, Q1, H_points, header, api_id)?;

    let T1 = proof.Bbar * proof.challenge + proof.Abar * proof.e_cap + proof.D * proof.r1_cap;
    let mut Bv = generators.g1_base_point + Q1 * domain;

    for i in 0..R {
        Bv += H_points[disclosed_indexes[i]] * disclosed_messages[i].value;
    }

    let mut T2 = Bv * proof.challenge + proof.D * proof.r3_cap;

    for j in 0..U {
        T2 += H_points[undisclosed_indexes[j]] * proof.m_cap[j];
    }

    Ok(ProofInitResult {
        Abar: proof.Abar,
        Bbar: proof.Bbar,
        D: proof.D,
        T1,
        T2,
        domain,
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
    pub fn new(s_cap: Scalar, m_cap: Vec<Scalar>, challenge: Scalar) -> Self {
        Self {
            s_cap,
            m_cap,
            challenge,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend_from_slice(&self.s_cap.to_bytes_be());
        self.m_cap
            .iter()
            .for_each(|s| bytes.extend_from_slice(&s.to_bytes_be()));
        bytes.extend_from_slice(&self.challenge.to_bytes_be());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let s_cap = Scalar::from_bytes_be(
            &<[u8; 32]>::try_from(&bytes[0..32])
                .map_err(|_| Error::InvalidProofOfKnowledgeSignature)?,
        )?;

        let mut m_cap: Vec<Scalar> = Vec::new();

        for chunk in bytes[32..].chunks_exact(32) {
            let b =
                <[u8; 32]>::try_from(chunk).map_err(|_| Error::InvalidProofOfKnowledgeSignature)?;
            m_cap.push(Scalar::from_bytes_be(&b)?);
        }

        let challenge = m_cap.pop().ok_or(Error::InvalidProofOfKnowledgeSignature)?; //at least the challenge should be present (even if all attributes are disclosed)

        Ok(Self {
            s_cap,
            m_cap,
            challenge,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        bbsplus::{
            ciphersuites::BbsCiphersuite, commitment::BlindFactor, keys::BBSplusPublicKey,
            proof::seeded_random_scalars, signature::BBSplusSignature,
        },
        schemes::{
            algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
            generics::{PoKSignature, Signature},
        },
        utils::util::bbsplus_utils::{get_messages_vec, ScalarExt},
    };
    use elliptic_curve::hash2curve::ExpandMsg;

    //mocked_rng - SHA256 - UPDATED
    #[test]
    fn mocked_rng_sha256() {
        mocked_rng::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "mockedRng.json");
    }

    //mocked_rng - SHAKE256 - UPDATED
    #[test]
    fn mocked_rng_shake256() {
        mocked_rng::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "mockedRng.json");
    }

    //SIGNATURE POK

    macro_rules! proof_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { proof_check::<$t>($p, $f); }
        )+)+ }
    }

    proof_tests! {
        (BbsBls12381Sha256, "./fixture_data/bls12-381-sha-256/"): {
            (proof_check_sha256_1, "proof/proof001.json"),
            (proof_check_sha256_2, "proof/proof002.json"),
            (proof_check_sha256_3, "proof/proof003.json"),
            (proof_check_sha256_4, "proof/proof004.json"),
            (proof_check_sha256_5, "proof/proof005.json"),
            (proof_check_sha256_6, "proof/proof006.json"),
            (proof_check_sha256_7, "proof/proof007.json"),
            (proof_check_sha256_8, "proof/proof008.json"),
            (proof_check_sha256_9, "proof/proof009.json"),
            (proof_check_sha256_10, "proof/proof010.json"),
            (proof_check_sha256_11, "proof/proof011.json"),
            (proof_check_sha256_12, "proof/proof012.json"),
            (proof_check_sha256_13, "proof/proof013.json"),
            (proof_check_sha256_14, "proof/proof014.json"),
            (proof_check_sha256_15, "proof/proof015.json"),
        },
        (BbsBls12381Shake256, "./fixture_data/bls12-381-shake-256/"): {
            (proof_check_shake256_1, "proof/proof001.json"),
            (proof_check_shake256_2, "proof/proof002.json"),
            (proof_check_shake256_3, "proof/proof003.json"),
            (proof_check_shake256_4, "proof/proof004.json"),
            (proof_check_shake256_5, "proof/proof005.json"),
            (proof_check_shake256_6, "proof/proof006.json"),
            (proof_check_shake256_7, "proof/proof007.json"),
            (proof_check_shake256_8, "proof/proof008.json"),
            (proof_check_shake256_9, "proof/proof009.json"),
            (proof_check_shake256_10, "proof/proof010.json"),
            (proof_check_shake256_11, "proof/proof011.json"),
            (proof_check_shake256_12, "proof/proof012.json"),
            (proof_check_shake256_13, "proof/proof013.json"),
            (proof_check_shake256_14, "proof/proof014.json"),
            (proof_check_shake256_15, "proof/proof015.json"),
        },
    }

    // BLIND PROOF OF KNOWLEDGE OF A SIGNATURE

    macro_rules! blind_proof_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { blind_proof_check::<$t>($p, $f, "./fixture_data_blind/"); }
        )+)+ }
    }

    blind_proof_tests! {
        (BbsBls12381Sha256, "./fixture_data_blind/bls12-381-sha-256/"): {
            (blind_proof_check_sha256_1, "proof/proof001.json"),
            (blind_proof_check_sha256_2, "proof/proof002.json"),
            (blind_proof_check_sha256_3, "proof/proof003.json"),
            (blind_proof_check_sha256_4, "proof/proof004.json"),
            (blind_proof_check_sha256_5, "proof/proof005.json"),
            (blind_proof_check_sha256_6, "proof/proof006.json"),
            (blind_proof_check_sha256_7, "proof/proof007.json"),
            (blind_proof_check_sha256_8, "proof/proof008.json"),
        },
        (BbsBls12381Shake256, "./fixture_data_blind/bls12-381-shake-256/"): {
            (blind_proof_check_shake256_1, "proof/proof001.json"),
            (blind_proof_check_shake256_2, "proof/proof002.json"),
            (blind_proof_check_shake256_3, "proof/proof003.json"),
            (blind_proof_check_shake256_4, "proof/proof004.json"),
            (blind_proof_check_shake256_5, "proof/proof005.json"),
            (blind_proof_check_shake256_6, "proof/proof006.json"),
            (blind_proof_check_shake256_7, "proof/proof007.json"),
            (blind_proof_check_shake256_8, "proof/proof008.json"),
        },
    }

    fn mocked_rng<S: Scheme>(pathname: &str, filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data =
            std::fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
        let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        eprintln!("Mocked Random Scalars");

        let seed_ = hex::decode(res["seed"].as_str().unwrap()).unwrap();
        let dst = hex::decode(res["dst"].as_str().unwrap()).unwrap();
        let count: usize = res["count"].as_u64().unwrap().try_into().unwrap();

        let mocked_scalars_hex: Vec<&str> = res["mockedScalars"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();

        let r = seeded_random_scalars::<S::Ciphersuite>(count, &seed_, &dst);

        let mut results = true;

        for i in 0..count {
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

    fn proof_check<S: Scheme>(pathname: &str, proof_filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = std::fs::read_to_string([pathname, proof_filename].concat())
            .expect("Unable to read file");
        let proof_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");

        let signerPK_hex = proof_json["signerPublicKey"].as_str().unwrap();
        let header_hex = proof_json["header"].as_str().unwrap();
        let ph_hex = proof_json["presentationHeader"].as_str().unwrap();
        let input_messages: Vec<String> = proof_json["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| serde_json::from_value(m.clone()).unwrap())
            .collect();

        let proof_expected = proof_json["proof"].as_str().unwrap();
        let result_expected = proof_json["result"]["valid"].as_bool().unwrap();

        let ph = hex::decode(ph_hex).unwrap();

        let revealed_message_indexes: Vec<usize> = proof_json["disclosedIndexes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| serde_json::from_value(m.clone()).unwrap())
            .collect();

        //Get Message Signature
        let signature_expected = proof_json["signature"].as_str().unwrap();

        let signature = Signature::<BBSplus<S::Ciphersuite>>::from_bytes(
            hex::decode(signature_expected)
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let header = hex::decode(header_hex).unwrap();
        let PK = BBSplusPublicKey::from_bytes(&hex::decode(signerPK_hex).unwrap()).unwrap();

        let msgs: Vec<Vec<u8>> = input_messages
            .iter()
            .map(|m| hex::decode(m).unwrap())
            .collect();

        let proof = PoKSignature::<BBSplus<S::Ciphersuite>>::proof_gen(
            &PK,
            &signature.to_bytes(),
            Some(&header),
            Some(&ph),
            Some(&msgs),
            Some(&revealed_message_indexes),
        )
        .unwrap();
        let my_encoded_proof = hex::encode(&proof.to_bytes());
        let result0 = proof_expected == my_encoded_proof;
        let result1 = result0 == result_expected;
        if result1 == false {
            println!("  proofGen: {}", result1);
            println!("  Expected: {}", proof_expected);
            println!("  Computed: {}", my_encoded_proof);
            assert!(result1, "Failed");
        }

        // Verify the Proof
        let disclosed_messages = get_messages_vec(&msgs, &revealed_message_indexes);

        let PROOF = PoKSignature::<BBSplus<S::Ciphersuite>>::from_bytes(
            &hex::decode(proof_expected).unwrap(),
        )
        .unwrap();

        let result2 = PROOF
            .proof_verify(
                &PK,
                Some(&disclosed_messages),
                Some(&revealed_message_indexes),
                Some(&header),
                Some(&ph),
            )
            .is_ok();
        let result3 = result2 == result_expected;
        if !result3 {
            eprintln!("  proofVerify: {}", result3);
            eprintln!("  Expected: {}", result_expected);
            eprintln!("  Computed: {}", result2);
            assert!(result3, "failed");
        } else {
            eprintln!("  Expected: {}", signature_expected);
            eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));

            eprintln!("  proofVerify: {}", result3);
            eprintln!("  Expected: {}", result_expected);
            eprintln!("  Computed: {}", result2);
            if result_expected == false {
                eprintln!(
                    "{} ({})",
                    result3,
                    proof_json["result"]["reason"].as_str().unwrap()
                );
            }
        }
    }

    fn blind_proof_check<S: Scheme>(pathname: &str, proof_filename: &str, messages_path: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = std::fs::read_to_string([pathname, proof_filename].concat())
            .expect("Unable to read file");
        let proof_json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");

        let messages_data = std::fs::read_to_string([messages_path, "messages.json"].concat())
            .expect("Unable to read file");
        let messages_json: serde_json::Value =
            serde_json::from_str(&messages_data).expect("Unable to parse");

        println!("{}", proof_json["caseName"]);

        let pk_hex = proof_json["signerPublicKey"].as_str().unwrap();

        let pk = BBSplusPublicKey::from_bytes(&hex::decode(pk_hex).unwrap()).unwrap();

        let committed_messages: Option<Vec<String>> = messages_json["committedMessages"]
            .as_array()
            .and_then(|cm| {
                cm.iter()
                    .map(|m| serde_json::from_value(m.clone()).unwrap())
                    .collect()
            });
        let committed_messages: Option<Vec<Vec<u8>>> = match committed_messages {
            Some(cm) => Some(cm.iter().map(|m| hex::decode(m).unwrap()).collect()),
            None => None,
        };

        let messages: Option<Vec<String>> = messages_json["messages"].as_array().and_then(|cm| {
            cm.iter()
                .map(|m| serde_json::from_value(m.clone()).unwrap())
                .collect()
        });
        let messages: Option<Vec<Vec<u8>>> = match messages {
            Some(m) => Some(m.iter().map(|m| hex::decode(m).unwrap()).collect()),
            None => None,
        };

        let secret_prover_blind = proof_json["proverBlind"].as_str().map(|b| {
            BlindFactor::from_bytes(&hex::decode(b).unwrap().try_into().unwrap()).unwrap()
        });
        let signer_blind = proof_json["signerBlind"].as_str().map(|b| {
            BlindFactor::from_bytes(&hex::decode(b).unwrap().try_into().unwrap()).unwrap()
        });
        let header = hex::decode(proof_json["header"].as_str().unwrap()).unwrap();
        let ph = hex::decode(proof_json["presentationHeader"].as_str().unwrap()).unwrap();
        let signature = BBSplusSignature::from_bytes(
            &hex::decode(proof_json["signature"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();

        let (disclosed_messages, disclosed_indexes) = proof_json["revealedMessages"]
            .as_object()
            .map(|values| {
                let messages = values
                    .values()
                    .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
                    .collect::<Vec<_>>();
                let indexes = values
                    .keys()
                    .map(|s| s.parse().unwrap())
                    .collect::<Vec<_>>();
                (messages, indexes)
            })
            .map_or((None, None), |(m, i)| (Some(m), Some(i))); // unzip() in 1.66+

        let (disclosed_committed_messages, disclosed_commitment_indexes) = proof_json
            ["revealedCommittedMessages"]
            .as_object()
            .map(|values| {
                let messages = values
                    .values()
                    .map(|h| hex::decode(h.as_str().unwrap()).unwrap())
                    .collect::<Vec<_>>();
                let indexes = values
                    .keys()
                    .map(|s| s.parse().unwrap())
                    .collect::<Vec<_>>();
                (messages, indexes)
            })
            .map_or((None, None), |(m, i)| (Some(m), Some(i))); // unzip() in 1.66+

        let used_committed_messages = if disclosed_commitment_indexes.is_some() {
            committed_messages
        } else {
            None
        };

        let proof = PoKSignature::<BBSplus<S::Ciphersuite>>::blind_proof_gen(
            &pk,
            &signature.to_bytes(),
            Some(&header),
            Some(&ph),
            messages.as_deref(),
            used_committed_messages.as_deref(),
            disclosed_indexes.as_deref(),
            disclosed_commitment_indexes.as_deref(),
            secret_prover_blind.as_ref(),
            signer_blind.as_ref(),
        )
        .unwrap();

        let expected_proof = proof_json["proof"].as_str().unwrap();

        assert_eq!(hex::encode(proof.to_bytes()), expected_proof);

        let result = proof
            .blind_proof_verify(
                &pk,
                Some(&header),
                Some(&ph),
                messages.as_ref().map(Vec::len),
                disclosed_messages.as_deref(),
                disclosed_committed_messages.as_deref(),
                disclosed_indexes.as_deref(),
                disclosed_commitment_indexes.as_deref(),
            )
            .is_ok();

        let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

        assert_eq!(result, expected_result);
    }
}
