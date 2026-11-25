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
            commitment::{BlindFactor, Message},
            keys::{BBSplusPublicKey, BBSplusSecretKey},
            test_utils::{hex_value, parse_messages, read_fixture},
        },
        schemes::{
            algorithms::{BBSplus, BbsBls12381Sha256, BbsBls12381Shake256, Scheme},
            generics::BlindSignature,
        },
    };
    use bls12_381_plus::Scalar;

    /// A blind signature test vector (`signature/signatureXXX.json`).
    struct SignCase {
        sk: BBSplusSecretKey,
        pk: BBSplusPublicKey,
        header: Vec<u8>,
        messages: Vec<Message>,
        blind_messages: Vec<Message>,
        commitment_with_proof: Option<Vec<u8>>,
        prover_blind: Option<BlindFactor>,
        signature: Vec<u8>,
        valid: bool,
    }

    impl SignCase {
        fn load(path: &str) -> Self {
            let json = read_fixture(path);
            println!("{}", json["caseName"]);
            Self {
                sk: BBSplusSecretKey::from_bytes(&hex_value(&json["signerKeyPair"]["secretKey"])).unwrap(),
                pk: BBSplusPublicKey::from_bytes(&hex_value(&json["signerKeyPair"]["publicKey"])).unwrap(),
                header: hex_value(&json["header"]),
                messages: parse_messages(&json["messages"]),
                blind_messages: parse_messages(&json["blindMessages"]),
                commitment_with_proof: json["commitmentWithProof"].as_str().map(|_| hex_value(&json["commitmentWithProof"])),
                prover_blind: json["proverBlind"].as_str().map(|_| {
                    BlindFactor::from_bytes(&hex_value(&json["proverBlind"]).try_into().unwrap()).unwrap()
                }),
                signature: hex_value(&json["signature"]),
                valid: json["result"]["valid"].as_bool().unwrap(),
            }
        }

        fn sign<S: Scheme>(&self, commitment_with_proof: Option<&[u8]>) -> Result<BlindSignature<BBSplus<S::Ciphersuite>>, crate::errors::Error>
        where
            S::Ciphersuite: BbsCiphersuite,
        {
            BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(
                &self.sk,
                &self.pk,
                commitment_with_proof,
                Some(&self.header),
                Some(&self.messages),
            )
        }

        fn signature<S: Scheme>(&self) -> BlindSignature<BBSplus<S::Ciphersuite>>
        where
            S::Ciphersuite: BbsCiphersuite,
        {
            BlindSignature::<BBSplus<S::Ciphersuite>>::from_bytes(&self.signature.clone().try_into().unwrap()).unwrap()
        }
    }

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
    {
        let case = SignCase::load(&[pathname, filename].concat());

        let signature = case.sign::<S>(case.commitment_with_proof.as_deref()).unwrap();
        assert_eq!(hex::encode(signature.to_bytes()), hex::encode(&case.signature));

        let result = signature
            .verify_blind_sign(
                &case.pk,
                Some(&case.header),
                Some(&case.messages),
                Some(&case.blind_messages),
                case.prover_blind.as_ref(),
            )
            .is_ok();
        assert_eq!(result, case.valid);
    }

    // NEGATIVE TESTS (BLIND-08)

    const SHA256_SIGNATURES: &str = "./fixture_data/fixture_data_blind/bls12-381-sha-256/signature/";
    const SHAKE256_SIGNATURES: &str = "./fixture_data/fixture_data_blind/bls12-381-shake-256/signature/";

    fn check_rejects_malformed_commitment<S: Scheme>(dir: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        // Multiple blind and signer messages, with a commitment.
        let case = SignCase::load(&[dir, "signature004.json"].concat());
        let commitment = case.commitment_with_proof.clone().unwrap();
        assert!(case.sign::<S>(Some(&commitment)).is_ok());

        let mut cases: Vec<(&str, Vec<u8>)> = vec![
            ("point only", commitment[..48].to_vec()),
            ("a single scalar", commitment[..48 + 32].to_vec()),
            ("truncated", commitment[..commitment.len() - 1].to_vec()),
        ];
        let mut trailing = commitment.clone();
        trailing.push(0);
        cases.push(("trailing byte", trailing));
        let mut zero_scalar = commitment.clone();
        zero_scalar.extend([0u8; 32]);
        cases.push(("extra zero scalar", zero_scalar));
        let mut extra_m = commitment.clone();
        extra_m.extend(&commitment[48..80]);
        cases.push(("one m^ too many", extra_m));
        let mut tampered = commitment.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        cases.push(("tampered challenge", tampered));

        for (name, c) in cases {
            assert!(case.sign::<S>(Some(&c)).is_err(), "commitment '{name}' should be rejected");
        }
    }

    #[test]
    fn blind_sign_rejects_malformed_commitment() {
        check_rejects_malformed_commitment::<BbsBls12381Sha256>(SHA256_SIGNATURES);
        check_rejects_malformed_commitment::<BbsBls12381Shake256>(SHAKE256_SIGNATURES);
    }

    fn flip_flag(m: &Message) -> Message {
        match m {
            Message::Hash(v) => Message::Raw(v.clone()),
            Message::Raw(v) => Message::Hash(v.clone()),
        }
    }

    fn check_verify_rejects_wrong_inputs<S: Scheme>(dir: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
    {
        let case = SignCase::load(&[dir, "signature004.json"].concat());
        let signature = case.signature::<S>();
        let prover_blind = case.prover_blind.as_ref().unwrap();

        let verify = |header: &[u8], messages: &[Message], blind_messages: &[Message], blind: Option<&BlindFactor>| {
            signature
                .verify_blind_sign(&case.pk, Some(header), Some(messages), Some(blind_messages), blind)
                .is_ok()
        };

        assert!(verify(&case.header, &case.messages, &case.blind_messages, Some(prover_blind)));

        // secret_prover_blind
        let wrong_blind = BlindFactor(prover_blind.0 + Scalar::ONE);
        assert!(!verify(&case.header, &case.messages, &case.blind_messages, Some(&wrong_blind)), "wrong prover blind");
        assert!(!verify(&case.header, &case.messages, &case.blind_messages, None), "missing prover blind");

        // header
        let mut header = case.header.clone();
        header.push(0);
        assert!(!verify(&header, &case.messages, &case.blind_messages, Some(prover_blind)), "different header");
        assert!(!verify(&[], &case.messages, &case.blind_messages, Some(prover_blind)), "empty header");

        // issuer / blind split
        assert!(!verify(&case.header, &case.blind_messages, &case.messages, Some(prover_blind)), "swapped lists");
        let mut fewer = case.messages.clone();
        let mut more = vec![fewer.pop().unwrap()];
        more.extend(case.blind_messages.iter().cloned());
        assert!(!verify(&case.header, &fewer, &more, Some(prover_blind)), "issuer message moved to the blind list");
        let all: Vec<Message> = case.messages.iter().chain(&case.blind_messages).cloned().collect();
        assert!(!verify(&case.header, &all, &[], Some(prover_blind)), "all messages as issuer messages");

        // single message changed or with the other flag
        for i in 0..case.messages.len() {
            let mut messages = case.messages.clone();
            messages[i] = Message::Hash(b"tampered".to_vec());
            assert!(!verify(&case.header, &messages, &case.blind_messages, Some(prover_blind)), "issuer message {i} changed");
            messages[i] = flip_flag(&case.messages[i]);
            assert!(!verify(&case.header, &messages, &case.blind_messages, Some(prover_blind)), "issuer message {i} flag");
        }
        for i in 0..case.blind_messages.len() {
            let mut blind_messages = case.blind_messages.clone();
            blind_messages[i] = Message::Hash(b"tampered".to_vec());
            assert!(!verify(&case.header, &case.messages, &blind_messages, Some(prover_blind)), "blind message {i} changed");
            blind_messages[i] = flip_flag(&case.blind_messages[i]);
            assert!(!verify(&case.header, &case.messages, &blind_messages, Some(prover_blind)), "blind message {i} flag");
        }

        // a signature without commitment must not verify with a blind factor or blind messages
        let no_commit = SignCase::load(&[dir, "signature005.json"].concat());
        let signature = no_commit.signature::<S>();
        let verify = |blind_messages: &[Message], blind: Option<&BlindFactor>| {
            signature
                .verify_blind_sign(&no_commit.pk, Some(&no_commit.header), Some(&no_commit.messages), Some(blind_messages), blind)
                .is_ok()
        };
        assert!(verify(&[], None));
        assert!(!verify(&[], Some(prover_blind)), "unexpected prover blind");
        assert!(!verify(&case.blind_messages, None), "unexpected blind messages");
    }

    #[test]
    fn verify_blind_sign_rejects_wrong_inputs() {
        check_verify_rejects_wrong_inputs::<BbsBls12381Sha256>(SHA256_SIGNATURES);
        check_verify_rejects_wrong_inputs::<BbsBls12381Shake256>(SHAKE256_SIGNATURES);
    }
}
