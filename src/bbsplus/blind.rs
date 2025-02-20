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

use super::{
    commitment::BlindFactor,
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
        util::bbsplus_utils::{calculate_domain, hash_to_scalar, ScalarExt},
    },
};
use bls12_381_plus::{G1Projective, Scalar, group::Curve};
use elliptic_curve::hash2curve::ExpandMsg;

impl<CS: BbsCiphersuite> BlindSignature<BBSplus<CS>> {
    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures#name-blind-signature-generation
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
    /// * `messages` (OPTIONAL), a vector of octet strings. If not supplied, it defaults to the empty array.
    ///
    /// # Output:
    /// a [`BlindSignature::BBSplus`] or [`Error`].
    ///
    pub fn blind_sign(
        sk: &BBSplusSecretKey,
        pk: &BBSplusPublicKey,
        commitment_with_proof: Option<&[u8]>,
        header: Option<&[u8]>,
        messages: Option<&[Vec<u8>]>,
    ) -> Result<Self, Error> {
        let messages = messages.unwrap_or(&[]);
        let L = messages.len();
        let commitment_with_proof = commitment_with_proof.unwrap_or(&[]);

        let mut M: usize = commitment_with_proof.len();
        if M != 0 {
            M = M
                .checked_sub(G1Projective::COMPRESSED_BYTES)
                .ok_or(Error::InvalidCommitmentProof)?;
            M = M
                .checked_sub(Scalar::BYTES)
                .ok_or(Error::InvalidCommitmentProof)?;
            M = M
                .checked_div(Scalar::BYTES)
                .ok_or(Error::InvalidCommitmentProof)?;
        }
            
        let generators = Generators::create::<CS>(L + 1, Some(CS::API_ID_BLIND));
        let blind_generators =
            Generators::create::<CS>(M + 1, Some(&[b"BLIND_", CS::API_ID_BLIND].concat()));

        let commit: G1Projective = Commitment::<BBSplus<CS>>::deserialize_and_validate_commit(
            Some(commitment_with_proof),
            &blind_generators,
            Some(CS::API_ID_BLIND)
        )?;
        
        let message_scalars: Vec<BBSplusMessage> = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID_BLIND)?;

        let mut B: Vec<G1Projective> = calculate_b(&generators, commit, message_scalars)?;

        let B_val = B.pop().unwrap();

        let blind_sig = finalize_blind_sign::<CS>(
            sk,
            pk,
            B_val,
            &generators,
            &blind_generators,
            header,
            Some(CS::API_ID_BLIND),
        )?;

        Ok(Self::BBSplus(blind_sig))
    }

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures#name-blind-signature-verificatio
    ///
    /// # Description
    /// This operation validates a blind BBS signature ([`BBSplusSignature`]), given the Signer's public key (PK),
    /// a header (header), a set of known to the Signer messages (messages) and if used, a set of committed messages
    /// (committed_messages) and the `secret_prover_blind` as returned by the [`Commitment::commit`] operation and
    /// a blind factor supplied by the Signer (`signer_blind`). This operation makes use of the [`core_verify`] operation
    ///
    /// # Inputs:
    /// * `self`, a signature
    /// * `pk` (REQUIRED), a public key
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    /// * `messages` (OPTIONAL), a vector of octet strings messages supplied by the Signer.  If not supplied, it defaults to the empty array.
    /// * `committed_messages` (OPTIONAL), a vector of octet strings messages committed by the Prover.
    /// * `secret_prover_blind` (OPTIONAL), a scalar value ([`BlindFactor`]). If not supplied it defaults to zero "0"
    ///
    /// # Output:
    /// a result: [`Ok`] or [`Error`].
    ///
    pub fn verify(
        &self,
        pk: &BBSplusPublicKey,
        header: Option<&[u8]>,
        messages: Option<&[Vec<u8>]>,
        committed_messages: Option<&[Vec<u8>]>,
        secret_prover_blind: Option<&BlindFactor>,
    ) -> Result<(), Error> {
        let api_id: &[u8] = CS::API_ID_BLIND;
        let messages = messages.unwrap_or(&[]);
        let committed_messages = committed_messages.unwrap_or(&[]);
        let secret_prover_blind = secret_prover_blind.unwrap_or(&BlindFactor(Scalar::ZERO));
        
        let (message_scalars, generators) = prepare_parameters::<CS>(
            Some(messages),
            Some(committed_messages),
            messages.len() + 1,
            committed_messages.len() + 1,
            Some(secret_prover_blind), 
            Some(api_id)
        )?;

        core_verify::<CS>(
            pk,
            self.bbsPlusBlindSignature(),
            &message_scalars,
            generators,
            header,
            Some(api_id),
        )
    }

    pub fn A(&self) -> G1Projective {
        match self {
            Self::BBSplus(inner) => inner.A,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn e(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.e,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn bbsPlusBlindSignature(&self) -> &BBSplusSignature {
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn to_bytes(&self) -> [u8; BBSplusSignature::BYTES] {
        self.bbsPlusBlindSignature().to_bytes()
    }

    pub fn from_bytes(data: &[u8; BBSplusSignature::BYTES]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusSignature::from_bytes(data)?))
    }
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures#name-prepare-parameters
///
/// 
/// # Inputs:
/// * `messages` (OPTIONAL), a vector of octet strings. If not supplied, it defaults to the empty array "()".
/// * `committed_messages ` (OPTIONAL), a vector of octet strings. If not supplied, it defaults to the empty array "()".
/// * `generators_number ` (REQUIRED), the number of generators.
/// * `blind_generators_number ` (REQUIRED), the number of blind generators.
/// * `message_scalars` (OPTIONAL), an array of scalar values. If not supplied, it defaults to the empty array ("()")
/// * `api_id ` (OPTIONAL), an octet string. If not supplied it defaults to the empty octet string ("")
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

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures#name-calculate-b-value
///
/// # Description
/// The B_calculate is defined to return an array of elements, to establish extendability of the scheme 
/// by allowing the B_calculate operation to return more elements than just the point to be signed.
///
/// # Inputs:
/// * `generators` (REQUIRED), an array of at least one point from the G1 group
/// * `commitment` (OPTIONAL), a point from the G1 group. If not supplied it defaults to the Identity_G1 point.
/// * `message_scalars` (OPTIONAL), an array of scalar values. If not supplied, it defaults to the empty array ("()")
/// 
/// # Output:
/// a [`Vec<G1Projective>`] an array of a single element from the G1 subgroup or [`Error`].
///
fn calculate_b(
    generators: &Generators,
    commitment: G1Projective,
    message_scalars: Vec<BBSplusMessage>,
) -> Result<Vec<G1Projective>, Error> {

    let L: usize = message_scalars.len();

    if generators.values.len() != L + 1 {
        return Err(Error::InvalidNumberOfGenerators);
    }
    
    let Q1: G1Projective = generators.values[0];
    let H_points: &[G1Projective] = &generators.values[1..];

    let mut B: G1Projective = Q1;
    for i in 0..L {
        B += H_points[i] * message_scalars[i].value;
    }

    B += commitment;

    if B.is_identity().into() {
        return Err(Error::G1IdentityError);
    }

    let mut b_value:Vec<G1Projective> = Vec::<G1Projective>::new();
    b_value.push(B);

    Ok(b_value)

}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-blind-signatures#name-finalize-blind-sign
///
/// # Description
/// This operation computes a blind BBS signature, from a secret key (SK), a set of generators (points of G1),
/// a header (header). The operation also accepts the identifier of the BBS Interface, calling this core operation.
///
/// # Inputs:
/// * `sk` (REQUIRED), a secret key
/// * `pk` (REQUIRED), a public key
/// * `B` (REQUIRED), a point of G1, different than Identity_G1. 
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application specific information.
/// * `api_id` (OPTIONAL), an octet string ([`BbsCiphersuite::API_ID_BLIND`]).
///                        If not supplied it defaults to the empty octet string ("")
///
/// # Output:
/// a [`BBSplusSignature`] or [`Error`].
///
fn finalize_blind_sign<CS>(
    sk: &BBSplusSecretKey,
    pk: &BBSplusPublicKey,
    B: G1Projective,
    generators: &Generators,
    blind_generators: &Generators,
    header: Option<&[u8]>,
    api_id: Option<&[u8]>,
) -> Result<BBSplusSignature, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let L  = generators.values.len() - 1;

    if L == 0 {
        return Err(Error::SignatureGenerationError("L value is 0".to_owned()));
    }

    let M  = blind_generators.values.len() - 1;

    if M == 0 {
        return Err(Error::SignatureGenerationError("M value is 0".to_owned()));
    }

    let Q1  = generators.values[0];
    //let Q2  = blind_generators.values[0];

    let api_id = api_id.unwrap_or(b"");
    let signature_dst = [api_id, CS::H2S].concat();

    let tmp_generators = [
        &generators.values[1..],
        //core::slice::from_ref(&Q2),
        &blind_generators
            .values
            .get(1..blind_generators.values.len() - 1)
            .unwrap_or_default(),
    ]
    .concat();

    let domain = calculate_domain::<CS>(pk, Q1, &tmp_generators, header, Some(api_id))?;

    let mut e_octs: Vec<u8> = Vec::new();
    e_octs.extend_from_slice(&sk.to_bytes());
    e_octs.extend_from_slice(&B.to_affine().to_compressed());
    e_octs.extend_from_slice(&domain.to_bytes_be());

    let e = hash_to_scalar::<CS>(&e_octs, &signature_dst)?; //TODO: Not sure where the Signature DST ("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIGNATURE_MOCK_RANDOM_SCALARS_DST_") in the fixtures is used

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

    macro_rules! sign_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { blind_sign::<$t>($p, $f); }
        )+)+ }
    }

    sign_tests! {
        (BbsBls12381Sha256, "./fixture_data_blind/bls12-381-sha-256/"): {
            (blind_sign_sha256_1, "signature/signature001.json"),
            (blind_sign_sha256_2, "signature/signature002.json"),
            (blind_sign_sha256_3, "signature/signature003.json"),
            (blind_sign_sha256_4, "signature/signature004.json"),
            (blind_sign_sha256_5, "signature/signature005.json"),
            (blind_sign_sha256_6, "signature/signature006.json"),
        },
        (BbsBls12381Shake256, "./fixture_data_blind/bls12-381-shake-256/"): {
            (blind_sign_shake256_1, "signature/signature001.json"),
            (blind_sign_shake256_2, "signature/signature002.json"),
            (blind_sign_shake256_3, "signature/signature003.json"),
            (blind_sign_shake256_4, "signature/signature004.json"),
            (blind_sign_shake256_5, "signature/signature005.json"),
            (blind_sign_shake256_6, "signature/signature006.json"),
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

        let signer_blind: Option<[u8; 32]> = match proof_json["signerBlind"] {
            serde_json::Value::Null => None,
            serde_json::Value::String(ref s) => Some(
                hex::decode(s)
                    .ok()
                    .and_then(|s| s.as_slice().try_into().ok())
                    .expect("invalid signerBlind"),
            ),
            _ => panic!("invalid signerBlind"),
        };
        let header = hex::decode(proof_json["header"].as_str().unwrap()).unwrap();
        let messages: Vec<String> = proof_json["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| serde_json::from_value(m.clone()).unwrap())
            .collect();
        let messages: Vec<Vec<u8>> = messages.iter().map(|m| hex::decode(m).unwrap()).collect();
        let signer_blind = signer_blind.and_then(|b| BlindFactor::from_bytes(&b).ok());
        let signature = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(
            &sk,
            &pk,
            commitment_with_proof.as_deref(),
            Some(&header),
            Some(&messages),
            //signer_blind.as_ref(),
        )
        .unwrap();
        let expected_signature = proof_json["signature"].as_str().unwrap();
        let signature_oct = signature.to_bytes();

        assert_eq!(hex::encode(&signature_oct), expected_signature);

        let result = signature
            .verify(
                &pk,
                Some(&header),
                Some(&messages),
                committed_messages.as_deref(),
                prover_blind.as_ref(),
            )
            .is_ok();

        let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

        assert_eq!(result, expected_result);
    }
}
