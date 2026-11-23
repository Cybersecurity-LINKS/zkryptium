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

//! # **Blind BBS Signature Extension**
//! The [Blind BBS Signature Extension](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05) builds on the BBS scheme
//! to support blind signing, where a signer can authenticate a message without knowing its content. This is achieved through a blinding process
//! applied to the message by the recipient before sending it to the signer. The signer then issues a signature over the blinded content, ensuring privacy.
//! Key features of the Blind BBS Signature Extension:
//! - **Message Blinding**: This extension allows recipients to obscure (blind) their messages before sending them to a signer.
//!                         This process ensures that the signer cannot learn the message's content.
//! 
//! Together, the BBS Signature Scheme and its Blind Signature Extension offer a robust solution for privacy-preserving
//! cryptographic systems, supporting applications in identity, authentication, and secure, anonymous transactions.
//! #Usage
//! 
//! ```toml
//! [dependencies]
//! zkryptium = { version = "0.8.3", default-features = false, features = ["bbsplus", "bbsplus_blind"] }
//! ```

use super::{
    commitment::{BBSplusCommitment, BlindFactor},
    keys::{BBSplusPublicKey, BBSplusSecretKey},
    signature::{core_verify, BBSplusSignature},
};
use crate::{
    bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators},
    errors::Error,
    schemes::{
        algorithms::BBSplus,
        generics::{BlindSignature, Commitment},
    },
    utils::{
        message::bbsplus_message::BBSplusMessage,
        util::bbsplus_utils::{calculate_domain, hash_to_scalar},
    },
};
use bls12_381_plus::{G1Projective, Scalar, group::Curve};
use elliptic_curve::hash2curve::ExpandMsg;
use crate::bbsplus::commitment::{messages_to_scalar, Message};

impl<CS: BbsCiphersuite> BlindSignature<BBSplus<CS>> {
    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-blind-signature-generation>
    ///
    /// # Description
    /// This operation returns a BBS blind signature from a secret key (SK), over a header,
    /// a set of messages and optionally a commitment value. If supplied, the commitment value must be accompanied by
    /// its proof of correctness (commitment_with_proof). The BlindSign operation makes use of the FinalizeBlindSign
    /// procedure and the B_calculate procedure defined. The B_calculate is defined to return an array of elements,
    /// to establish extendability of the scheme by allowing the B_calculate operation to return more elements
    /// than just the point to be signed.
    ///
    /// # Inputs:
    /// * `sk` (REQUIRED), a secret key
    /// * `pk` (REQUIRED), a public key
    /// * `commitment_with_proof` (OPTIONAL), an octet string, representing a serialized commitment and commitment_proof.
    ///                                       If not supplied, it defaults to the empty string ("").
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    /// * `messages` (OPTIONAL), a vector of [`Message`]. If not supplied, it defaults to the empty array.
    ///
    /// # Output:
    /// a [`BlindSignature::BBSplus`] or [`Error`].
    ///
    /// # Resource usage
    /// `commitment_with_proof` comes from the Prover and is not trusted. To verify it, the Signer
    /// must derive `M + 1` blind generators, where `M` is the number of committed messages encoded
    /// in it: each one costs a hash-to-curve. A malformed commitment is rejected before any
    /// generator is computed, but a well-formed one with many committed messages is processed in
    /// full before its proof is found invalid, so the cost grows linearly with its length
    /// (one hash-to-curve every 32 bytes).
    ///
    /// The library does not cap `M`, since the draft does not define a limit. Applications exposing
    /// this operation to untrusted Provers should bound the size of `commitment_with_proof`
    /// (for `M` committed messages it is `48 + 32 * (M + 2)` bytes) before calling it.
    ///
    pub fn blind_sign(
        sk: &BBSplusSecretKey,
        pk: &BBSplusPublicKey,
        commitment_with_proof: Option<&[u8]>,
        header: Option<&[u8]>,
        messages: Option<&[Message]>,
    ) -> Result<Self, Error> {
        let messages = messages.unwrap_or(&[]);
        let L = messages.len();
        let commitment_with_proof = commitment_with_proof.unwrap_or(&[]);

        // Number of blind generators used by the commitment, if any.
        // The draft derives M from length(commitment_with_proof) alone. Here the commitment is
        // parsed first (format, point, scalars), so a malformed input is rejected before paying
        // for the M + 1 hash-to-curve calls of create_generators. For well-formed inputs M is
        // the same value: commitment_with_proof = C || s^ || m^_1..m^_M || challenge.
        let M = if commitment_with_proof.is_empty() {
            0
        } else {
            BBSplusCommitment::from_bytes(commitment_with_proof)?.proof.m_cap.len()
        };
            
        let generators = Generators::create::<CS>(L + 1, Some(CS::API_ID_BLIND));

        let blind_generators =
            Generators::create::<CS>(M + 1, Some(&[b"BLIND_", CS::API_ID_BLIND].concat()));

        let commitment= Commitment::<BBSplus<CS>>::deserialize_and_validate_commit(
            Some(commitment_with_proof),
            &blind_generators,
            Some(CS::API_ID_BLIND)
        )?;

        let message_scalars = messages_to_scalar::<CS>(
            messages,
            Some(CS::API_ID_BLIND)
        )?;

        let mut B= calculate_b::<CS>(
            pk,
            &generators,
            &blind_generators,
            Some(commitment),
            message_scalars,
            header,
            Some(CS::API_ID_BLIND)
        )?;

        // B_calculate returns exactly one element: an empty result is an internal error.
        let B_val = B.pop().ok_or(Error::UnespectedError)?;

        let blind_sig = finalize_blind_sign::<CS>(
            sk,
            B_val,
            Some(CS::API_ID_BLIND),
        )?;

        Ok(Self::BBSplus(blind_sig))
    }

    /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-blind-signature-verificatio>
    ///
    /// # Description
    /// This operation validates a blind BBS signature (signature), given the Signer's public key (PK),
    /// a header (header), a set of messages (messages), including first the messages chosen by
    /// the Issuer and then the ones chosen (and committed to) by the Prover and if used,
    /// the secret_prover_blind as returned by the Commit operation.
    ///
    /// # Inputs:
    /// * `self`, a signature
    /// * `pk` (REQUIRED), a public key
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    /// * `messages` (OPTIONAL), a vector of [`Message`].  If not supplied, it defaults to the empty array.
    /// * `blind_messages ` (OPTIONAL), a vector of of [`Message`] committed by the Prover.
    /// * `secret_prover_blind` (OPTIONAL), a scalar value ([`BlindFactor`]). If not supplied it defaults to zero "0"
    ///
    /// # Output:
    /// a result: [`Ok`] or [`Error`].
    ///
    pub fn verify_blind_sign(
        &self,
        pk: &BBSplusPublicKey,
        header: Option<&[u8]>,
        messages: Option<&[Message]>,
        blind_messages: Option<&[Message]>,
        secret_prover_blind: Option<&BlindFactor>,
    ) -> Result<(), Error> {
        let api_id: &[u8] = CS::API_ID_BLIND;
        let messages = messages.unwrap_or(&[]);
        let blind_messages = blind_messages.unwrap_or(&[]);
        let secret_prover_blind = secret_prover_blind.unwrap_or(&BlindFactor(Scalar::ZERO));

        let L = messages.len();
        let M = blind_messages.len();

        let generators = Generators::create::<CS>(L + 1, Some(api_id));
        let blind_generators = Generators::create::<CS>(M + 1, Some(&[b"BLIND_",api_id].concat()));

        let signer_scalars = messages_to_scalar::<CS>(messages, Some(api_id))?;

        let mut committed_message_scalars = messages_to_scalar::<CS>(blind_messages, Some(api_id))?;

        let mut proof_scalars = signer_scalars;

        proof_scalars.push(secret_prover_blind.0);
        proof_scalars.append(&mut committed_message_scalars);

        let proof_scalars  = proof_scalars.iter()
                .map(|s| BBSplusMessage::new(*s))
                .collect::<Vec<BBSplusMessage>>();

        let mut gens = generators;
        gens.values.extend(blind_generators.values);

        core_verify::<CS>(
            pk,
            self.bbsPlusBlindSignature(),
            proof_scalars.as_slice(),
            gens,
            header,
            Some(api_id),
        )
    }

    /// Returns the `A` component of the BBS+ blind signature.
    pub fn A(&self) -> G1Projective {
        match self {
            Self::BBSplus(inner) => inner.A,
            _ => panic!("Cannot happen!"),
        }
    }

    /// Returns the `e` component of the BBS+ blind signature.
    pub fn e(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.e,
            _ => panic!("Cannot happen!"),
        }
    }

    /// Returns the BBS+ blind signature.
    pub fn bbsPlusBlindSignature(&self) -> &BBSplusSignature {
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }

    /// Converts the BBS+ blind signature to a byte array.
    pub fn to_bytes(&self) -> [u8; BBSplusSignature::BYTES] {
        self.bbsPlusBlindSignature().to_bytes()
    }

    /// Converts a byte array to a BBS+ blind signature.
    pub fn from_bytes(data: &[u8; BBSplusSignature::BYTES]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusSignature::from_bytes(data)?))
    }
}

/// Prepares message scalars and generators for the blind operations.
///
/// This helper comes from draft-irtf-cfrg-bbs-blind-signatures-02 (§"Prepare Parameters"), which
/// draft 05 no longer defines: the Blind BBS operations now build generators and scalars inline.
/// It is kept only for the per-verifier-linkability (pseudonym) operations, which still use it.
///
/// # Inputs:
/// * `messages` (OPTIONAL), a vector of octet strings. If not supplied, it defaults to the empty array "()".
/// * `committed_messages` (OPTIONAL), a vector of octet strings. If not supplied, it defaults to the empty array "()".
/// * `generators_number` (REQUIRED), the number of generators.
/// * `blind_generators_number` (REQUIRED), the number of blind generators.
/// * `secret_prover_blind` (OPTIONAL), a scalar value ([`BlindFactor`]). If not supplied, it defaults it defaults to zero "0"
/// * `api_id` (OPTIONAL), an octet string. If not supplied it defaults to the empty octet string ("")
/// 
/// # Output:
/// a [`(Vec<BBSplusMessage>, Generators)`] A vector message_scalars of scalar values and a vector generators of points from the G1 subgroup; or [`Error`].
///
pub fn prepare_parameters<CS>(
    messages: Option<&[Vec<u8>]>,
    committed_messages: Option<&[Vec<u8>]>,
    generators_number: usize,
    blind_generators_number: usize,
    secret_prover_blind: Option<&BlindFactor>,
    api_id: Option<&[u8]>
) -> Result<(Vec<BBSplusMessage>, Generators), Error> 
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
    {
        //TODO remove
    let messages = messages.unwrap_or(&[]);
    let committed_messages = committed_messages.unwrap_or(&[]);
    
    let api_id = api_id.unwrap_or(b"");

    let mut message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, api_id)?;

    let mut committed_message_scalars = Vec::<BBSplusMessage>::new();

    if let Some(secret_prover_blind ) = secret_prover_blind {
        committed_message_scalars.push(BBSplusMessage::new(secret_prover_blind.0));
        
    }

    committed_message_scalars.append(&mut BBSplusMessage::messages_to_scalar::<CS>(committed_messages, api_id)?);

    let generators = Generators::create::<CS>(generators_number, Some(api_id));

    let blind_generators = Generators::create::<CS>(
        blind_generators_number,
        Some(&[b"BLIND_", api_id].concat())
    );

    message_scalars.append(&mut committed_message_scalars);
    
    Ok((message_scalars, generators.append(blind_generators)))

}

/// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-calculate-b-value>
///
/// # Description
/// The B_calculate is defined to return an array of elements, to establish extendability of the scheme 
/// by allowing the B_calculate operation to return more elements than just the point to be signed.
///
/// # Inputs:
/// * `pk` (REQUIRED), a public key
/// * `generators` (REQUIRED), an array of at least one point from the G1 group
/// * `blind_generators` (OPTIONAL), vector of points of G1. If it is not supplied, it defaults to the empty set
/// * `commitment` (OPTIONAL), a point from the G1 group. If not supplied, it defaults to the Identity_G1 point.
/// * `message_scalars` (OPTIONAL), an array of scalar values. If not supplied, it defaults to the empty array ("()")
/// * `header` (OPTIONAL), an octet string containing context- and application-specific information
/// * `api_id` (OPTIONAL), octet string. If not supplied, it defaults to the empty octet string ("").
/// 
/// # Output:
/// a [`Vec<G1Projective>`] an array of a single element from the G1 subgroup or [`Error`].
///
pub fn calculate_b<CS: BbsCiphersuite>(
    pk: &BBSplusPublicKey,
    generators: &Generators,
    blind_generators: &Generators,
    commitment: Option<G1Projective>,
    message_scalars: Vec<Scalar>,
    header: Option<&[u8]>,
    api_id: Option<&[u8]>
) -> Result<Vec<G1Projective>, Error> {

    let commitment = commitment.unwrap_or(G1Projective::IDENTITY);

    let L = message_scalars.len();

    let M: isize  = blind_generators.values.len() as isize - 1;

    if generators.values.len() != L + 1 {
        return Err(Error::InvalidNumberOfGenerators);
    }

    if M < 0 {
        return Err(Error::InvalidNumberOfBlindGenerators);
    }

    let Q1 = generators.values[0];
    let H_points = &generators.values[1..];

    let mut domain_gens = generators.clone();
    domain_gens.values.append(&mut blind_generators.values.clone());

    let domain = calculate_domain::<CS>(
        pk,
        &domain_gens,
        header,
        api_id
    )?;

    let mut B = generators.g1_base_point;
    B += Q1 * domain;

    for i in 0..L {
        B += H_points[i] * message_scalars[i];
    }
    
    B += commitment;

    if B.is_identity().into() {
        return Err(Error::G1IdentityError);
    }

    let mut b_value:Vec<G1Projective> = Vec::<G1Projective>::new();
    b_value.push(B);

    Ok(b_value)

}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures-05#name-finalize-blind-sign
///
/// # Description
/// This operation computes a blind BBS signature from a secret key (SK) and the point to be signed (B).
///  The operation also accepts the identifier of the BBS Interface that calls this core operation.

///
/// # Inputs:
/// * `sk` (REQUIRED), a secret key
/// * `B` (REQUIRED), a point of G1, different than Identity_G1.
/// * `api_id` (OPTIONAL), an octet string ([`BbsCiphersuite::API_ID_BLIND`]).
///                        If not supplied, it defaults to the empty octet string ("")
///
/// # Output:
/// a [`BBSplusSignature`] or [`Error`].
///
pub(super) fn finalize_blind_sign<CS>(
    sk: &BBSplusSecretKey,
    B: G1Projective,
    api_id: Option<&[u8]>,
) -> Result<BBSplusSignature, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{

    let api_id = api_id.unwrap_or(b"");
    let signature_dst = [api_id, CS::H2S].concat();

    if B.is_identity().into() {
        return Err(Error::G1IdentityError);
    }

    let mut e_octs: Vec<u8> = Vec::new();

    e_octs.extend_from_slice(&sk.to_bytes());
    e_octs.extend_from_slice(&B.to_affine().to_compressed());

    let e = hash_to_scalar::<CS>(&e_octs, &signature_dst)?;
    
    let sk_e = sk.0 + e;
    let sk_e_inv = Option::<Scalar>::from(sk_e.invert())
        .ok_or_else(|| Error::BlindSignError("Invert scalar failed".to_owned()))?;
    let A = B * sk_e_inv;

    Ok(BBSplusSignature { A, e })
}

#[cfg(test)]
mod tests {
    use crate::{
        bbsplus::{
            ciphersuites::BbsCiphersuite,
            commitment::BlindFactor,
            keys::{BBSplusPublicKey, BBSplusSecretKey},
        },
        schemes::{
            algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
            generics::BlindSignature,
        },
    };
    use elliptic_curve::hash2curve::ExpandMsg;
    use std::fs;
    use serde_json::Value;
    use crate::bbsplus::commitment::Message;

    macro_rules! sign_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { blind_sign::<$t>($p, $f); }
        )+)+ }
    }

    sign_tests! {
        (BbsBls12381Sha256, "./fixture_data/fixture_data_blind/bls12-381-sha-256/"): {
            (blind_sign_sha256_1, "signature/signature001.json"),
            (blind_sign_sha256_2, "signature/signature002.json"),
            (blind_sign_sha256_3, "signature/signature003.json"),
            (blind_sign_sha256_4, "signature/signature004.json"),
            (blind_sign_sha256_5, "signature/signature005.json"),
        },
        (BbsBls12381Shake256, "./fixture_data/fixture_data_blind/bls12-381-shake-256/"): {
            (blind_sign_shake256_1, "signature/signature001.json"),
            (blind_sign_shake256_2, "signature/signature002.json"),
            (blind_sign_shake256_3, "signature/signature003.json"),
            (blind_sign_shake256_4, "signature/signature004.json"),
            (blind_sign_shake256_5, "signature/signature005.json"),
        },
    }

    fn blind_sign<S: Scheme>(pathname: &str, filename: &str)
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

        let prover_blind = proof_json["proverBlind"].as_str().map(|b| {
            BlindFactor::from_bytes(&hex::decode(b).unwrap().try_into().unwrap()).unwrap()
        });

        let commitment_with_proof = proof_json["commitmentWithProof"]
            .as_str()
            .map(|c| hex::decode(c).unwrap());

        let messages = parse_messages(&proof_json["messages"]);

        let blind_messages = parse_messages(&proof_json["blindMessages"]);

        let header = hex::decode(proof_json["header"].as_str().unwrap()).unwrap();

        let signature = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(
            &sk,
            &pk,
            commitment_with_proof.as_deref(),
            Some(&header),
            Some(&messages),
        ).unwrap();
        
        let expected_signature = proof_json["signature"].as_str().unwrap();
        let signature_oct = signature.to_bytes();

        assert_eq!(hex::encode(&signature_oct), expected_signature);

        let result = signature
            .verify_blind_sign(
                &pk,
                Some(&header),
                Some(&messages),
                Some(&blind_messages),
                prover_blind.as_ref(),
            )
            .is_ok();

        let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

        assert_eq!(result, expected_result);

    }

    #[test]
    fn blind_sign_rejects_malformed_commitment() {
        // BLIND-04: malformed commitments are rejected (now before the blind generators are created).
        type S = BbsBls12381Sha256;
        let path = "./fixture_data/fixture_data_blind/bls12-381-sha-256/signature/signature004.json";
        let data = fs::read_to_string(path).expect("Unable to read file");
        let json: Value = serde_json::from_str(&data).expect("Unable to parse");

        let sk = BBSplusSecretKey::from_bytes(
            &hex::decode(json["signerKeyPair"]["secretKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let pk = BBSplusPublicKey::from_bytes(
            &hex::decode(json["signerKeyPair"]["publicKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let header = hex::decode(json["header"].as_str().unwrap()).unwrap();
        let messages = parse_messages(&json["messages"]);
        let commitment = hex::decode(json["commitmentWithProof"].as_str().unwrap()).unwrap();

        let sign = |c: &[u8]| {
            BlindSignature::<BBSplus<<S as Scheme>::Ciphersuite>>::blind_sign(
                &sk,
                &pk,
                Some(c),
                Some(&header),
                Some(&messages),
            )
        };

        assert!(sign(&commitment).is_ok());

        let mut cases: Vec<Vec<u8>> = vec![
            commitment[..48].to_vec(),                 // point only
            commitment[..48 + 32].to_vec(),            // a single scalar
            commitment[..commitment.len() - 1].to_vec(), // truncated
        ];
        let mut extra = commitment.clone();
        extra.push(0);
        cases.push(extra); // trailing byte
        let mut zero_scalar = commitment.clone();
        zero_scalar.extend([0u8; 32]);
        cases.push(zero_scalar); // well aligned, but the extra scalar is zero
        let mut wrong_m = commitment.clone();
        wrong_m.extend(&commitment[48..80]);
        cases.push(wrong_m); // well-formed, one m^ too many: proof verification fails

        for c in cases {
            assert!(sign(&c).is_err(), "commitment of {} bytes should be rejected", c.len());
        }
    }

    fn parse_message(v: &Value) -> Message {
        let pair = v.as_array().expect("message: [flag, hex]");
        let flag = pair[0].as_str().expect("message: flag is not a string");
        let bytes = hex::decode(pair[1].as_str().expect("message: value not a string"))
                .expect("message: invalid hex");

        match flag {
            "HASH" => Message::Hash(bytes),
            "RAW" => Message::Raw(bytes),
            other => panic!("flag unknown: {other}"),
        }
    }

    pub fn parse_messages(v: &Value) -> Vec<Message> {
        v.as_array().unwrap_or(&Vec::new()).iter().map(parse_message).collect()
    }

}
