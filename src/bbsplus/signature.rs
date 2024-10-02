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
use super::keys::{BBSplusPublicKey, BBSplusSecretKey};
use crate::{
    bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators},
    errors::Error,
    schemes::{algorithms::BBSplus, generics::Signature},
    utils::{
        message::bbsplus_message::BBSplusMessage,
        util::bbsplus_utils::{
            calculate_domain, hash_to_scalar, parse_g1_projective, serialize, ScalarExt,
        },
    },
};
use bls12_381_plus::{multi_miller_loop, G1Projective, G2Prepared, G2Projective, Gt, Scalar};
use elliptic_curve::{group::Curve, hash2curve::ExpandMsg};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusSignature {
    pub A: G1Projective,
    pub e: Scalar,
}

impl BBSplusSignature {
    pub const BYTES: usize = 80;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; Self::BYTES];
        bytes[0..G1Projective::COMPRESSED_BYTES]
            .copy_from_slice(&self.A.to_affine().to_compressed());
        let e = self.e.to_be_bytes();
        bytes[G1Projective::COMPRESSED_BYTES..Self::BYTES].copy_from_slice(&e);
        bytes
    }

    pub fn from_bytes(data: &[u8; Self::BYTES]) -> Result<Self, Error> {
        let A: G1Projective = parse_g1_projective(&data[0..G1Projective::COMPRESSED_BYTES])
            .map_err(|_| Error::InvalidSignature)?;
        let e = Scalar::from_bytes_be(&data[G1Projective::COMPRESSED_BYTES..Self::BYTES])
            .map_err(|_| Error::InvalidSignature)?;

        Ok(Self { A, e })
    }
}

impl<CS: BbsCiphersuite> Signature<BBSplus<CS>> {
    pub fn a(&self) -> G1Projective {
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

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-signature-generation-sign
    /// # Description
    /// The `sign` API returns a BBS signature from a secret key (SK), over a header and a set of messages.
    ///
    /// # Inputs:
    /// * `messages` (OPTIONAL), a vector of octet strings representing the messages, it could be an empty vector.
    /// * `sk` (REQUIRED), a secret key
    /// * `pk` (REQUIRED), a public key
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    ///
    /// # Output:
    /// * new [`Signature::BBSplus`] or [`Error`]
    pub fn sign(
        messages: Option<&[Vec<u8>]>,
        sk: &BBSplusSecretKey,
        pk: &BBSplusPublicKey,
        header: Option<&[u8]>,
    ) -> Result<Self, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let messages = messages.unwrap_or(&[]);
        let message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID)?;
        let generators = Generators::create::<CS>(messages.len() + 1, Some(CS::API_ID));
        let signature = core_sign::<CS>(
            sk,
            pk,
            generators,
            header,
            &message_scalars,
            Some(CS::API_ID),
        )?;

        Ok(Self::BBSplus(signature))
    }

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-signature-verification-veri
    /// # Description
    /// The `verify` API validates a BBS signature, given a public key (PK), a header and a set of messages
    /// # Inputs:
    /// * `self`, the signature
    /// * `pk` (REQUIRED), a public key
    /// * `messages` (OPTIONAL), a vector of octet strings representing the messages, it could be an empty vector.
    /// * `header` (OPTIONAL), an octet string containing context and application specific information.
    ///
    /// # Output:
    /// * a result either [`Ok()`] or [`Error`]
    pub fn verify(
        &self,
        pk: &BBSplusPublicKey,
        messages: Option<&[Vec<u8>]>,
        header: Option<&[u8]>,
    ) -> Result<(), Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let messages = messages.unwrap_or(&[]);
        let message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID)?;
        let generators = Generators::create::<CS>(messages.len() + 1, Some(CS::API_ID));
        let signature = self.bbsPlusSignature();

        core_verify::<CS>(
            pk,
            signature,
            &message_scalars,
            generators,
            header,
            Some(CS::API_ID),
        )
    }

    pub fn bbsPlusSignature(&self) -> &BBSplusSignature {
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn to_bytes(&self) -> [u8; BBSplusSignature::BYTES] {
        self.bbsPlusSignature().to_bytes()
    }

    pub fn from_bytes(data: &[u8; BBSplusSignature::BYTES]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusSignature::from_bytes(data)?))
    }

    /// # Description
    /// Update signature with a new value of a signed message
    ///
    /// # Inputs:
    /// * `sk` (REQUIRED), Signer private key.
    /// * `old_message` (REQUIRED), message octet string old value.
    /// * `new_message` (REQUIRED), message octet string new value.
    /// * `update_index` (REQUIRED), index of the message to update.
    /// * `n` (REQUIRED), total number of signed messages.
    ///
    /// # Output:
    /// * new [`BBSplusSignature`] or [`Error`]
    pub fn update_signature(
        &self,
        sk: &BBSplusSecretKey,
        old_message: &[u8],
        new_message: &[u8],
        update_index: usize,
        n: usize,
    ) -> Result<Self, Error> {
        let generators = Generators::create::<CS>(n + 1, Some(CS::API_ID));

        if generators.values.len() <= update_index + 1 {
            return Err(Error::UpdateSignatureError(
                "len(generators) <= update_index".to_owned(),
            ));
        }

        let old_message_scalar =
            BBSplusMessage::map_message_to_scalar_as_hash::<CS>(old_message, CS::API_ID)?;
        let new_message_scalar =
            BBSplusMessage::map_message_to_scalar_as_hash::<CS>(new_message, CS::API_ID)?;

        let H_points = &generators.values[1..];
        let H_i = H_points.get(update_index).ok_or(Error::Unspecified)?;
        let sk_e = sk.0 + self.e();
        let mut B = self.a() * sk_e;
        B = B + (-H_i * old_message_scalar.value);
        B = B + (H_i * new_message_scalar.value);

        let sk_e_inv = Option::<Scalar>::from(sk_e.invert())
            .ok_or_else(|| Error::UpdateSignatureError("Invert scalar failed".to_owned()))?;
        let A = B * sk_e_inv;

        if A == G1Projective::IDENTITY {
            return Err(Error::UpdateSignatureError("A == IDENTITY G1".to_owned()));
        }

        return Ok(Self::BBSplus(BBSplusSignature { A, e: self.e() }));
    }
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-coresign
/// # Description
/// This operation computes a deterministic signature from a secret key (SK), a set of generators (points of G1) and optionally a header and a vector of messages.
///
/// # Inputs:
/// * `sk` (REQUIRED), a secret key
/// * `pk` (REQUIRED), a public key
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application specific information.
/// * `messages` (REQUIRED), a vector of scalars (`BBSplusMessage`) representing the messages, it could be an empty vector.
/// * `api_id` (OPTIONAL), an octet string. If not supplied it defaults to theempty octet string ("").
///
/// # Output:
/// * new [`BBSplusSignature`] or [`Error`]
fn core_sign<CS>(
    sk: &BBSplusSecretKey,
    pk: &BBSplusPublicKey,
    generators: Generators,
    header: Option<&[u8]>,
    messages: &[BBSplusMessage],
    api_id: Option<&[u8]>,
) -> Result<BBSplusSignature, Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let L = messages.len();

    if generators.values.len() != L + 1 {
        return Err(Error::NotEnoughGenerators);
    }

    let Q1 = generators.values[0];
    let H_points = &generators.values[1..];

    let api_id = api_id.unwrap_or(b"");

    let signature_dst = [api_id, CS::H2S].concat();

    let domain = calculate_domain::<CS>(pk, Q1, H_points, header, Some(api_id))?;

    // Serialize
    let input: Vec<Scalar> = core::iter::once(sk.0)
        .chain(messages.iter().map(|m| m.value))
        .chain(core::iter::once(domain))
        .collect();

    let e = hash_to_scalar::<CS>(&serialize(&input), &signature_dst)?;

    // B = P1 + Q_1 * domain + H_1 * msg_1 + ... + H_L * msg_L

    let mut B = generators.g1_base_point + Q1 * domain;

    for i in 0..L {
        B = B + H_points[i] * messages[i].value;
    }

    // A = B * (1 / (SK + e))
    let A = B * (sk.0 + e).invert().unwrap();

    if A == G1Projective::IDENTITY {
        return Err(Error::SignatureGenerationError(
            "A == Identity_G1".to_owned(),
        ));
    }

    Ok(BBSplusSignature { A, e: e })
}

/// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-coreverify
/// # Description
/// This operation checks that a signature is valid for a given set of generators, header and vector of messages, against a supplied public key (PK). The set of messages MUST be supplied in this operation in the same order they were supplied to `core_sign` when creating the signature.
///
/// # Inputs:
/// * `pk` (REQUIRED), a public key
/// * `signature` (REQUIRED), a `BBSplusSignature`
/// * `messages` (REQUIRED), a vector of scalars (`BBSplusMessage`) representing the messages, it could be an empty vector.
/// * `generators` (REQUIRED), vector of pseudo-random points in G1.
/// * `header` (OPTIONAL), an octet string containing context and application specific information.
/// * `api_id` (OPTIONAL), an octet string. If not supplied it defaults to theempty octet string ("").
///
/// # Output:
/// * a result either [`Ok()`] or [`Error`]
pub(super) fn core_verify<CS>(
    pk: &BBSplusPublicKey,
    signature: &BBSplusSignature,
    messages: &[BBSplusMessage],
    generators: Generators,
    header: Option<&[u8]>,
    api_id: Option<&[u8]>,
) -> Result<(), Error>
where
    CS: BbsCiphersuite,
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let L = messages.len();

    if generators.values.len() != L + 1 {
        return Err(Error::NotEnoughGenerators);
    }

    let Q1 = generators.values[0];
    let H_points: &[G1Projective] = &generators.values[1..];

    let domain = calculate_domain::<CS>(pk, Q1, H_points, header, api_id)?;

    let mut B = generators.g1_base_point + Q1 * domain;

    for i in 0..L {
        B = B + H_points[i] * messages[i].value;
    }

    let BP2 = G2Projective::GENERATOR;
    let A2 = pk.0 + BP2 * signature.e;

    let identity_GT = Gt::IDENTITY;

    let term1 = (&signature.A.to_affine(), &G2Prepared::from(A2.to_affine()));
    let term2 = (&B.to_affine(), &G2Prepared::from(-BP2.to_affine()));

    let pairing = multi_miller_loop(&[term1, term2]).final_exponentiation();

    if pairing == identity_GT {
        Ok(())
    } else {
        Err(Error::SignatureVerificationError)
    }
}

#[cfg(test)]
mod tests {

    use crate::bbsplus::ciphersuites::BbsCiphersuite;
    use crate::keys::pair::KeyPair;
    use crate::schemes::algorithms::Scheme;
    use crate::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
    use crate::{
        bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey},
        schemes::{algorithms::BBSplus, generics::Signature},
    };
    use elliptic_curve::hash2curve::ExpandMsg;
    use std::fs;

    //MSG SIGNATURE

    macro_rules! msg_tests {
        ( $( ($t:ident, $p:literal): { $( ($n:ident, $f:literal), )+ },)+ ) => { $($(
            #[test] fn $n() { msg_signature::<$t>($p, $f); }
        )+)+ }
    }

    msg_tests! {
        (BbsBls12381Sha256, "./fixture_data/bls12-381-sha-256/"): {
            (msg_signature_sha256_1, "signature/signature001.json"),
            (msg_signature_sha256_2, "signature/signature002.json"),
            (msg_signature_sha256_3, "signature/signature003.json"),
            (msg_signature_sha256_4, "signature/signature004.json"),
            (msg_signature_sha256_5, "signature/signature005.json"),
            (msg_signature_sha256_6, "signature/signature006.json"),
            (msg_signature_sha256_7, "signature/signature007.json"),
            (msg_signature_sha256_8, "signature/signature008.json"),
            (msg_signature_sha256_9, "signature/signature009.json"),
            (msg_signature_sha256_10, "signature/signature010.json"),
        },
        (BbsBls12381Shake256, "./fixture_data/bls12-381-shake-256/"): {
            (msg_signature_shake256_1, "signature/signature001.json"),
            (msg_signature_shake256_2, "signature/signature002.json"),
            (msg_signature_shake256_3, "signature/signature003.json"),
            (msg_signature_shake256_4, "signature/signature004.json"),
            (msg_signature_shake256_5, "signature/signature005.json"),
            (msg_signature_shake256_6, "signature/signature006.json"),
            (msg_signature_shake256_7, "signature/signature007.json"),
            (msg_signature_shake256_8, "signature/signature008.json"),
            (msg_signature_shake256_9, "signature/signature009.json"),
            (msg_signature_shake256_10, "signature/signature010.json"),
        },
    }

    //Update Signature - SHA256
    #[test]
    fn update_signature_sha256() {
        update_signature::<BbsBls12381Sha256>();
    }

    //Update Blinded Signature - SHAKE256
    #[test]
    fn update_signature_shake256() {
        update_signature::<BbsBls12381Shake256>();
    }

    fn msg_signature<S: Scheme>(pathname: &str, filename: &str)
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        let data = fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
        let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
        eprintln!("{}", res["caseName"]);

        let header_hex = res["header"].as_str().unwrap();
        let msgs_hex: Vec<String> = res["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| serde_json::from_value(m.clone()).unwrap())
            .collect();
        let SK_hex = res["signerKeyPair"]["secretKey"].as_str().unwrap();
        let PK_hex = res["signerKeyPair"]["publicKey"].as_str().unwrap();
        let SIGNATURE_expected = res["signature"].as_str().unwrap();
        let RESULT_expected = res["result"]["valid"].as_bool().unwrap();

        let header = hex::decode(header_hex).unwrap();
        let SK = BBSplusSecretKey::from_bytes(&hex::decode(SK_hex).unwrap()).unwrap();
        let PK = BBSplusPublicKey::from_bytes(&hex::decode(PK_hex).unwrap()).unwrap();

        let messages: Vec<Vec<u8>> = msgs_hex.iter().map(|m| hex::decode(m).unwrap()).collect();

        let signature =
            Signature::<BBSplus<S::Ciphersuite>>::sign(Some(&messages), &SK, &PK, Some(&header))
                .unwrap();

        let result0 = hex::encode(signature.to_bytes()) == SIGNATURE_expected;

        let result1 = result0 == RESULT_expected;
        if !result1 {
            eprintln!("  SIGN: {}", result1);
            eprintln!("  Expected: {}", SIGNATURE_expected);
            eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));
            assert!(result1, "failed")
        }

        //Verify the signature

        let signature_expected = Signature::<BBSplus<S::Ciphersuite>>::from_bytes(
            &hex::decode(SIGNATURE_expected).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let result2 = signature_expected
            .verify(&PK, Some(&messages), Some(&header))
            .is_ok();
        let result3 = result2 == RESULT_expected;

        if !result3 {
            eprintln!("  VERIFY: {}", result3);
            eprintln!("  Expected: {}", RESULT_expected);
            eprintln!("  Computed: {}", result2);
            assert!(result3, "failed");
        } else {
            eprintln!("  SIGN: {}", result1);
            eprintln!("  Expected: {}", SIGNATURE_expected);
            eprintln!("  Computed: {}", hex::encode(signature.to_bytes()));

            eprintln!("  VERIFY: {}", result3);
            eprintln!("  Expected: {}", RESULT_expected);
            eprintln!("  Computed: {}", result2);
            if RESULT_expected == false {
                eprintln!(
                    "{} ({})",
                    result3,
                    res["result"]["reason"].as_str().unwrap()
                );
            }
        }
    }

    fn update_signature<S: Scheme>()
    where
        S::Ciphersuite: BbsCiphersuite,
        <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
    {
        const IKM: &str = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
        const KEY_INFO: &str = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";
        const msgs: [&str; 3] = [
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "87a8bd656d49ee07b8110e1d8fd4f1dcef6fb9bc368c492d9bc8c4f98a739ac6",
            "96012096adda3f13dd4adbe4eea481a4c4b5717932b73b00e31807d3c5894b90",
        ];
        const header_hex: &str = "11223344556677889900aabbccddeeff";
        let header = hex::decode(header_hex).unwrap();

        let keypair = KeyPair::<BBSplus<S::Ciphersuite>>::generate(
            &hex::decode(&IKM).unwrap(),
            Some(&hex::decode(&KEY_INFO).unwrap()),
            None,
        )
        .unwrap();

        let sk = keypair.private_key();
        let pk = keypair.public_key();

        let messages: Vec<Vec<u8>> = msgs.iter().map(|m| hex::decode(m).unwrap()).collect();

        let signature =
            Signature::<BBSplus<S::Ciphersuite>>::sign(Some(&messages), sk, pk, Some(&header))
                .unwrap();
        let verify = signature.verify(pk, Some(&messages), Some(&header)).is_ok();

        assert!(verify, "Signature NOT VALID!");

        const new_message: &str =
            "8872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
        const update_index: usize = 0usize;

        let new_message_bytes = hex::decode(new_message).unwrap();
        let old_message_bytes = messages.get(update_index).unwrap();

        let updated_signature = signature
            .update_signature(
                sk,
                &old_message_bytes,
                &new_message_bytes,
                update_index,
                messages.len(),
            )
            .unwrap();

        let mut new_messages = messages.clone();
        new_messages[update_index] = new_message_bytes;

        let verify = updated_signature
            .verify(pk, Some(&new_messages), Some(&header))
            .is_ok();

        assert!(verify, "Signature NOT VALID!");

        const new_message_wrong: &str =
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f01";
        let new_message_bytes_wrong = hex::decode(new_message_wrong).unwrap();
        let mut new_messages_wrong = messages.clone();
        new_messages_wrong[update_index] = new_message_bytes_wrong;

        let verify = updated_signature
            .verify(pk, Some(&new_messages_wrong), Some(&header))
            .is_ok();

        assert!(!verify, "Signature MUST BE NOT VALID!");
    }
}
