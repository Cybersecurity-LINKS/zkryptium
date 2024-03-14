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


//TODO: add documentation

use std::panic;
use bls12_381_plus::{G1Projective, Scalar};
use elliptic_curve::hash2curve::ExpandMsg;
use crate::{bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, errors::Error, schemes::{algorithms::BBSplus, generics::{BlindSignature, Commitment}}, utils::{message::BBSplusMessage, util::bbsplus_utils::{calculate_domain, hash_to_scalar, ScalarExt}}};
use super::{commitment::BlindFactor, keys::{BBSplusPublicKey, BBSplusSecretKey}, signature::{core_verify, BBSplusSignature}};


impl <CS:BbsCiphersuite> BlindSignature<BBSplus<CS>> {

    pub fn blind_sign(sk: &BBSplusSecretKey, pk: &BBSplusPublicKey, commitment_with_proof: Option<&[u8]>, header: Option<&[u8]>, messages: Option<&[Vec<u8>]>, signer_blind: Option<&BlindFactor>) -> Result<Self, Error>{
        let messages = messages.unwrap_or(&[]);
        let L = messages.len();
        let commitment_with_proof = commitment_with_proof.unwrap_or(&[]);
        let mut M = commitment_with_proof.len();
        if M != 0 {
            M = M.checked_sub(G1Projective::COMPRESSED_BYTES).ok_or(Error::InvalidCommitmentProof)?;
            M = M.checked_sub(Scalar::BYTES).ok_or(Error::InvalidCommitmentProof)?;
            M = M.checked_div(Scalar::BYTES).ok_or(Error::InvalidCommitmentProof)?;
        }

        let generators = Generators::create::<CS>(M + L + 1, Some(CS::API_ID_BLIND));

        let message_scalars = BBSplusMessage::messages_to_scalar::<CS>(messages, CS::API_ID_BLIND)?;

        let blind_sig = core_blind_sign::<CS>(sk,
            pk,
            &generators,
            commitment_with_proof,
            header,
            &message_scalars,
            signer_blind,
            Some(CS::API_ID_BLIND)
        )?;

        Ok(Self::BBSplus(blind_sig))

    }

    pub fn verify(&self, pk: &BBSplusPublicKey, header: Option<&[u8]>, messages: Option<&[Vec<u8>]>, committed_messages: Option<&[Vec<u8>]>, secret_prover_blind: Option<&BlindFactor>, signer_blind: Option<&BlindFactor>) -> Result<(), Error>{
        let messages = messages.unwrap_or(&[]);
        let committed_messages = committed_messages.unwrap_or(&[]);

        let mut message_scalars = Vec::new();

        let secret_prover_blind= secret_prover_blind.unwrap_or(&BlindFactor(Scalar::ZERO));

        if secret_prover_blind.0 != Scalar::ZERO {
            let signer_blind = signer_blind.unwrap_or(&BlindFactor(Scalar::ZERO));
            let message = BBSplusMessage::new(secret_prover_blind.0 + signer_blind.0);
            message_scalars.push(message);
        }

        let api_id = CS::API_ID_BLIND;
        message_scalars.extend(BBSplusMessage::messages_to_scalar::<CS>(committed_messages, api_id)?);
        message_scalars.extend(BBSplusMessage::messages_to_scalar::<CS>(messages, api_id)?);

        let generators = Generators::create::<CS>(message_scalars.len()+1, Some(api_id));

        core_verify::<CS>(pk, self.bbsPlusBlindSignature(), &message_scalars, generators, header, Some(api_id))
    }

    pub fn A(&self) -> G1Projective {
        match self {
            Self::BBSplus(inner) => inner.A,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn e(&self) -> Scalar {
        match self {
            Self::BBSplus(inner) => inner.e,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn bbsPlusBlindSignature(&self) -> &BBSplusSignature{
        match self {
            Self::BBSplus(inner) => inner,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn to_bytes(&self) -> [u8; BBSplusSignature::BYTES] {
        self.bbsPlusBlindSignature().to_bytes()
    }

    pub fn from_bytes(data: &[u8; BBSplusSignature::BYTES]) -> Result<Self, Error> {
        Ok(Self::BBSplus(BBSplusSignature::from_bytes(data)?))
    }

}



fn core_blind_sign<CS>(
        sk: &BBSplusSecretKey,
        pk: &BBSplusPublicKey,
        generators: &Generators,
        commitment_with_proof: &[u8],
        header: Option<&[u8]>,
        messages: &[BBSplusMessage],
        signer_blind: Option<&BlindFactor>,
        api_id: Option<&[u8]>) -> Result<BBSplusSignature, Error>
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let api_id = api_id.unwrap_or(b"");
        let signature_dst = [api_id, CS::H2S].concat();
        let L = messages.len();

        let (mut commit, M) = Commitment::<BBSplus<CS>>::deserialize_and_validate_commit(Some(commitment_with_proof), generators, Some(api_id))?;
        let Q1 = generators.values[0];

        let Q2 = if commitment_with_proof.is_empty() {
            G1Projective::IDENTITY
        } else {
            generators.values[1]
        };

        let signer_blind = signer_blind.unwrap_or(&BlindFactor(Scalar::ZERO));

        let H_points = &generators.values[M+1..M+L+1];

        let temp_generators = &generators.values[1..M+L+1];

        let domain = calculate_domain::<CS>(pk, Q1, temp_generators, header, Some(api_id))?;

        let mut e_octs: Vec<u8> = Vec::new();
        e_octs.extend_from_slice(&sk.to_bytes());
        e_octs.extend_from_slice(&domain.to_bytes_be());
        messages.iter().map(|&p| p.value.to_bytes_be()).for_each(|a| e_octs.extend_from_slice(&a));
        if signer_blind.0 != Scalar::ZERO {
            e_octs.extend_from_slice(&signer_blind.to_bytes());
        }
        e_octs.extend_from_slice(commitment_with_proof);

        let e = hash_to_scalar::<CS>(&e_octs, &signature_dst)?; //TODO: Not sure where the Signature DST ("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_SIGNATURE_MOCK_RANDOM_SCALARS_DST_") in the fixtures is used
        if signer_blind.0 != Scalar::ZERO {
            commit += Q2 * signer_blind.0;
        }

        let mut B = generators.g1_base_point + Q1 * domain;

        for i in 0..L {
            B += H_points[i] * messages[i].value;
        }

        B += commit;

        let sk_e = sk.0 + e;
        let sk_e_inv = Option::<Scalar>::from(sk_e.invert()).ok_or(Error::BlindSignError("Invert scalar failed".to_owned()))?;
        let A = B * sk_e_inv;


        Ok(BBSplusSignature{A, e})
    }




    #[cfg(test)]
    mod tests {
        use std::fs;
        use elliptic_curve::hash2curve::ExpandMsg;
        use crate::{bbsplus::{ciphersuites::BbsCiphersuite, commitment::BlindFactor, keys::{BBSplusPublicKey, BBSplusSecretKey}}, schemes::{algorithms::{BBSplus, Scheme, BBS_BLS12381_SHA256}, generics::BlindSignature}};
    
    
        //Blind Sign - SHA256 - UPDATED
        #[test]
        fn blind_sign_sha256_1() {
            blind_sign::<BBS_BLS12381_SHA256>("./fixture_data_blind/bls12-381-sha-256/", "signature/signature001.json");
        }

        #[test]
        fn blind_sign_sha256_2() {
            blind_sign::<BBS_BLS12381_SHA256>("./fixture_data_blind/bls12-381-sha-256/", "signature/signature002.json");
        }

        #[test]
        fn blind_sign_sha256_3() {
            blind_sign::<BBS_BLS12381_SHA256>("./fixture_data_blind/bls12-381-sha-256/", "signature/signature003.json");
        }

        #[test]
        fn blind_sign_sha256_4() {
            blind_sign::<BBS_BLS12381_SHA256>("./fixture_data_blind/bls12-381-sha-256/", "signature/signature004.json");
        }

        #[test]
        fn blind_sign_sha256_5() {
            blind_sign::<BBS_BLS12381_SHA256>("./fixture_data_blind/bls12-381-sha-256/", "signature/signature005.json");
        }

        #[test]
        fn blind_sign_sha256_6() {
            blind_sign::<BBS_BLS12381_SHA256>("./fixture_data_blind/bls12-381-sha-256/", "signature/signature006.json");
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

            let committed_messages: Option<Vec<String>>= proof_json["committedMessages"].as_array().and_then(|cm| cm.iter().map(|m| serde_json::from_value(m.clone()).unwrap()).collect());
            let prover_blind = proof_json["proverBlind"].as_str().map(|b| BlindFactor::from_bytes(&hex::decode(b).unwrap().try_into().unwrap()).unwrap());
            
            let commitment_with_proof = proof_json["commitmentWithProof"].as_str().map(|c| hex::decode(c).unwrap());

            let committed_messages: Option<Vec<Vec<u8>>> = match committed_messages {
                Some(cm) => Some(cm.iter().map(|m| hex::decode(m).unwrap()).collect()),
                None => None,
            };

            let signer_blind: Option<[u8; 32]> = proof_json["signerBlind"].as_str().and_then(|s| hex::decode(s).ok()).and_then(|b| b.try_into().ok());
            let header = hex::decode(proof_json["header"].as_str().unwrap()).unwrap();
            let messages: Vec<String> = proof_json["messages"].as_array().unwrap().iter().map(|m| serde_json::from_value(m.clone()).unwrap()).collect();
            let messages: Vec<Vec<u8>> = messages.iter().map(|m| hex::decode(m).unwrap()).collect();
            let signer_blind = signer_blind.and_then(|b| BlindFactor::from_bytes(&b).ok());
            let signature = BlindSignature::<BBSplus<S::Ciphersuite>>::blind_sign(&sk, &pk, commitment_with_proof.as_deref(), Some(&header), Some(&messages), signer_blind.as_ref()).unwrap();
            let expected_signature = proof_json["signature"].as_str().unwrap();
            let signature_oct= signature.to_bytes();

            assert_eq!(hex::encode(&signature_oct), expected_signature);

            let result = signature.verify(&pk, Some(&header), Some(&messages), committed_messages.as_deref(), prover_blind.as_ref(), signer_blind.as_ref()).is_ok();

            let expected_result = proof_json["result"]["valid"].as_bool().unwrap();

            assert_eq!(result, expected_result);
        }

    }