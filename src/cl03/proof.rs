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
    commitment::CL03Commitment,
    keys::{CL03CommitmentPublicKey, CL03PublicKey},
    signature::CL03Signature,
};
use crate::{
    cl03::{
        bases::Bases,
        ciphersuites::CLCiphersuite,
        range_proof::{Boudot2000RangeProof, RangeProof},
        sigma_protocols::{NISP2Commitments, NISPMultiSecrets, NISPSecrets, NISPSignaturePoK},
    },
    schemes::algorithms::CL03,
    schemes::generics::{Commitment, PoKSignature, ZKPoK},
    utils::message::cl03_message::CL03Message,
};
use digest::{Digest};
use rug::{ops::Pow, Integer};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
struct ProofOfValue {
    value: NISPSecrets,
    commitment: CL03Commitment,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03PoKSignature {
    spok: NISPSignaturePoK,
    range_proof_e: Boudot2000RangeProof,
    proofs_commited_mi: Vec<ProofOfValue>,
    range_proofs_commited_mi: Vec<Boudot2000RangeProof>,
}

impl<CS: CLCiphersuite> PoKSignature<CL03<CS>> {
    pub fn proof_gen(
        signature: &CL03Signature,
        commitment_pk: &CL03CommitmentPublicKey,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        messages: &[CL03Message],
        unrevealed_message_indexes: &[usize],
    ) -> Self
    where
        CS::HashAlg: Digest,
    {
        let min_e = Integer::from(2).pow(CS::le - 1) + 1;
        let max_e = Integer::from(2).pow(CS::le) - 1;
        let min_x = Integer::from(0);
        let max_x = Integer::from(2).pow(CS::lm) - 1;

        let spok = NISPSignaturePoK::nisp5_MultiAttr_generate_proof::<CS>(
            signature,
            commitment_pk,
            signer_pk,
            a_bases,
            messages,
            unrevealed_message_indexes,
        );

        //range proof e
        let r_proof_e = match CS::RANGEPROOF_ALG {
            RangeProof::Boudot2000 => Boudot2000RangeProof::prove::<CS::HashAlg>(
                &signature.e,
                &spok.Ce,
                &commitment_pk.g_bases[0],
                &commitment_pk.h,
                &commitment_pk.N,
                &min_e,
                &max_e,
            ),
        };

        let mut proofs_mi: Vec<ProofOfValue> = Vec::new();
        let mut r_proofs_mi: Vec<Boudot2000RangeProof> = Vec::new();
        for i in unrevealed_message_indexes {
            let mi = messages
                .get(*i)
                .expect("unrevealed_message_indexes not valid with respect to the messages!");
            let gi = &commitment_pk.g_bases.get(*i).expect(
                "unrevealed_message_indexes not valid with respect to the commitment_pk.g_bases!",
            );
            let cmi = Commitment::<CL03<CS>>::commit_with_commitment_pk(
                messages,
                commitment_pk,
                Some(&[*i]),
            )
            .cl03Commitment()
            .to_owned();
            let proof_mi_ri = NISPSecrets::nisp2sec_generate_proof::<CS>(
                mi,
                &cmi,
                &gi,
                &commitment_pk.h,
                &commitment_pk.N,
            );
            proofs_mi.push(ProofOfValue {
                value: proof_mi_ri,
                commitment: cmi.clone(),
            });
            let r_proof_mi = match CS::RANGEPROOF_ALG {
                RangeProof::Boudot2000 => Boudot2000RangeProof::prove::<CS::HashAlg>(
                    &mi.value,
                    &cmi,
                    &gi,
                    &commitment_pk.h,
                    &commitment_pk.N,
                    &min_x,
                    &max_x,
                ),
            };

            r_proofs_mi.push(r_proof_mi);
        }

        Self::CL03(CL03PoKSignature {
            spok,
            range_proof_e: r_proof_e,
            proofs_commited_mi: proofs_mi,
            range_proofs_commited_mi: r_proofs_mi,
        })
    }

    pub fn proof_verify(
        &self,
        commitment_pk: &CL03CommitmentPublicKey,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        messages: &[CL03Message],
        unrevealed_message_indexes: &[usize],
        n_signed_messages: usize,
    ) -> bool
    where
        CS::HashAlg: Digest,
    {
        let min_e = Integer::from(2).pow(CS::le - 1) + 1;
        let max_e = Integer::from(2).pow(CS::le) - 1;
        let min_x = Integer::from(0);
        let max_x = Integer::from(2).pow(CS::lm) - 1;
        let CLSPoK = self.to_cl03_proof();
        let boolean_spok = NISPSignaturePoK::nisp5_MultiAttr_verify_proof::<CS>(
            &CLSPoK.spok,
            commitment_pk,
            signer_pk,
            a_bases,
            messages,
            unrevealed_message_indexes,
            n_signed_messages,
        );
        if !boolean_spok {
            println!("Signature PoK Failed!");
            return false;
        }
        if CLSPoK.spok.Ce.value == CLSPoK.range_proof_e.E {
            //Verify RANGE PROOFS e
            let boolean_rproof_e = CLSPoK.range_proof_e.verify::<CS::HashAlg>(
                &commitment_pk.g_bases[0],
                &commitment_pk.h,
                &commitment_pk.N,
                &min_e,
                &max_e,
            );

            if boolean_rproof_e {
                //Verify RANGE PROOFS mi
                let mut idx: usize = 0;
                for i in unrevealed_message_indexes {
                    let gi = &commitment_pk.g_bases.get(*i).expect("unrevealed_message_indexes not valid with respect to the commitment_pk.g_bases!");
                    let ProofOfValue {
                        value: proof_mi,
                        commitment: cmi,
                    } = CLSPoK.proofs_commited_mi.get(idx).expect("index overflow");

                    let boolean_proof_mi = proof_mi.nisp2sec_verify_proof::<CS>(
                        &cmi,
                        gi,
                        &commitment_pk.h,
                        &commitment_pk.N,
                    );
                    if !boolean_proof_mi {
                        println!("Knowledge verification of mi Failed!");
                        return false;
                    }

                    let boolean_rproofs_mi = CLSPoK
                        .range_proofs_commited_mi
                        .get(idx)
                        .expect("index overflow")
                        .verify::<CS::HashAlg>(
                            &gi,
                            &commitment_pk.h,
                            &commitment_pk.N,
                            &min_x,
                            &max_x,
                        );
                    if !boolean_rproofs_mi {
                        println!("Range proof verification on mi Failed!");
                        return false;
                    }
                    idx += 1;
                }
            } else {
                println!("Range proof verification on e Failed!");
                return false;
            }
        } else {
            println!("Commitment on 'e' used in the SPoK different from the one used in the Range Proof!");
            return false;
        }

        true
    }

    pub fn to_cl03_proof(&self) -> &CL03PoKSignature {
        match self {
            Self::CL03(inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03ZKPoK {
    proof_C_Ctrusted: Option<NISP2Commitments>,
    proof_commited_msgs: NISPMultiSecrets,
    proofs_commited_mi: Vec<ProofOfValue>,
    range_proofs_mi: Vec<Boudot2000RangeProof>,
    proof_r: ProofOfValue,
    range_proof_r: Boudot2000RangeProof,
}

impl CL03ZKPoK {}

impl<CS: CLCiphersuite> ZKPoK<CL03<CS>> {
    pub fn generate_proof(
        messages: &[CL03Message],
        C: &CL03Commitment,
        C_trusted: Option<&CL03Commitment>,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        commitment_pk: Option<&CL03CommitmentPublicKey>,
        unrevealed_message_indexes: &[usize],
    ) -> Self
    where
        CS::HashAlg: Digest,
    {
        let mut proof_C_Ctrusted: Option<NISP2Commitments> = None;
        if let Some(C_trusted) = C_trusted {
            if let Some(commitment_pk) = commitment_pk {
                proof_C_Ctrusted = Some(NISP2Commitments::nisp2_generate_proof_MultiSecrets::<CS>(
                    messages,
                    C,
                    &C_trusted,
                    signer_pk,
                    a_bases,
                    commitment_pk,
                    unrevealed_message_indexes,
                ));
            }
        }

        let proof_msgs = NISPMultiSecrets::nispMultiSecrets_generate_proof::<CS>(
            messages,
            C,
            signer_pk,
            a_bases,
            Some(unrevealed_message_indexes),
        );

        let min_x = Integer::from(0);
        let max_x = Integer::from(2).pow(CS::lm) - 1;
        //RANGE PROOF on unrevealde messages
        let mut proofs_mi: Vec<ProofOfValue> = Vec::new();
        let mut r_proofs_msgs: Vec<Boudot2000RangeProof> = Vec::new();
        for i in unrevealed_message_indexes {
            let mi = messages
                .get(*i)
                .expect("unreaveled_message_indexes not valid with respect to the messages!");
            let ai = &a_bases.0.get(*i).expect(
                "unreaveled_message_indexes not valid with respect to the commitment_pk.g_bases!",
            );
            let cmi =
                Commitment::<CL03<CS>>::commit_with_pk(&[mi.clone()], signer_pk, a_bases, None)
                    .cl03Commitment()
                    .to_owned();
            let proof_mi = NISPSecrets::nisp2sec_generate_proof::<CS>(
                mi,
                &cmi,
                &ai,
                &signer_pk.b,
                &signer_pk.N,
            );
            proofs_mi.push(ProofOfValue {
                value: proof_mi,
                commitment: cmi.clone(),
            });
            match CS::RANGEPROOF_ALG {
                RangeProof::Boudot2000 => {
                    let r_proof_mi = Boudot2000RangeProof::prove::<CS::HashAlg>(
                        &mi.value,
                        &cmi,
                        &ai,
                        &signer_pk.b,
                        &signer_pk.N,
                        &min_x,
                        &max_x,
                    );
                    r_proofs_msgs.push(r_proof_mi);
                }
            };
        }

        //RANGE PROOF on randomness of C
        let min_r = Integer::from(0);
        let max_r = Integer::from(2).pow(CS::ln) - 1;
        let r = CL03Message::new(C.randomness.clone());
        let cr = Commitment::<CL03<CS>>::commit_with_pk(&[r.clone()], &signer_pk, a_bases, None);
        let proof_r = ProofOfValue {
            value: NISPSecrets::nisp2sec_generate_proof::<CS>(
                &r,
                cr.cl03Commitment(),
                &a_bases.0[0],
                &signer_pk.b,
                &signer_pk.N,
            ),
            commitment: cr.cl03Commitment().to_owned(),
        };

        let rproof_r = match CS::RANGEPROOF_ALG {
            RangeProof::Boudot2000 => Boudot2000RangeProof::prove::<CS::HashAlg>(
                &r.value,
                cr.cl03Commitment(),
                &a_bases.0[0],
                &signer_pk.b,
                &signer_pk.N,
                &min_r,
                &max_r,
            ),
        };

        Self::CL03(CL03ZKPoK {
            proof_C_Ctrusted,
            proof_commited_msgs: proof_msgs,
            proofs_commited_mi: proofs_mi,
            range_proofs_mi: r_proofs_msgs,
            proof_r: proof_r,
            range_proof_r: rproof_r,
        })
    }

    pub fn verify_proof(
        &self,
        C: &CL03Commitment,
        C_trusted: Option<&CL03Commitment>,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        commitment_pk: Option<&CL03CommitmentPublicKey>,
        unrevealed_message_indexes: &[usize],
    ) -> bool
    where
        CS::HashAlg: Digest,
    {
        let zkpok = self.to_cl03_zkpok();

        let mut boolean_C_Ctrusted: bool = true;
        if let Some(C_trusted) = C_trusted {
            if let Some(commitment_pk) = commitment_pk {
                boolean_C_Ctrusted = zkpok
                    .proof_C_Ctrusted
                    .clone()
                    .unwrap()
                    .nisp2_verify_proof_MultiSecrets::<CS>(
                        C,
                        C_trusted,
                        signer_pk,
                        a_bases,
                        commitment_pk,
                        unrevealed_message_indexes,
                    );
            }
        }

        if !boolean_C_Ctrusted {
            println!("The trusted commitment is different from commitment received!");
            return false;
        }

        let boolean_proof_msgs = zkpok
            .proof_commited_msgs
            .nispMultiSecrets_verify_proof::<CS>(
                C,
                signer_pk,
                a_bases,
                Some(unrevealed_message_indexes),
            );

        if !boolean_proof_msgs {
            println!("Verification of the PoK of secrets Failed!");
            return false;
        }

        let min_x = Integer::from(0);
        let max_x = Integer::from(2).pow(CS::lm) - 1;
        let mut idx = 0usize;

        for i in unrevealed_message_indexes {
            let ai = &a_bases
                .0
                .get(*i)
                .expect("unreaveled_message_indexes not valid with respect to the messages!");
            let proof_mi = zkpok.proofs_commited_mi.get(idx).expect("index overflow");
            let boolean_proof_mi = proof_mi.value.nisp2sec_verify_proof::<CS>(
                &proof_mi.commitment,
                ai,
                &signer_pk.b,
                &signer_pk.N,
            );

            if !boolean_proof_mi {
                println!("Verification of the Proof of Knowledge of m{}. Failed!", i);
                return false;
            }
            let rproof_mi = zkpok.range_proofs_mi.get(idx).expect("index overflow");
            let boolean_rproof_mi =
                rproof_mi.verify::<CS::HashAlg>(&ai, &signer_pk.b, &signer_pk.N, &min_x, &max_x);
            if !boolean_rproof_mi {
                println!("Verification of the Range Proof of m{}. Failed", i);
                return false;
            }

            idx += 1;
        }

        let boolean_proof_r = zkpok.proof_r.value.nisp2sec_verify_proof::<CS>(
            &zkpok.proof_r.commitment,
            &a_bases.0[0],
            &signer_pk.b,
            &signer_pk.N,
        );
        if !boolean_proof_r {
            println!("Verification of the Proof of Knowledge of r. Failed!");
            return false;
        }

        let min_r = Integer::from(0);
        let max_r = Integer::from(2).pow(CS::ln) - 1;
        let boolean_rproof_r = zkpok.range_proof_r.verify::<CS::HashAlg>(
            &a_bases.0[0],
            &signer_pk.b,
            &signer_pk.N,
            &min_r,
            &max_r,
        );
        if !boolean_rproof_r {
            println!("Verification of the Range Proof of r. Failed");
            return false;
        }

        true
    }

    pub fn to_cl03_zkpok(&self) -> &CL03ZKPoK {
        match self {
            Self::CL03(inner) => &inner,
            _ => panic!("Cannot happen!"),
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::cl03::ciphersuites::CLCiphersuite;
    use crate::schemes::algorithms::CL03_CL1024_SHA256;
    use crate::{
        cl03::{bases::Bases, keys::CL03CommitmentPublicKey},
        keys::pair::KeyPair,
        schemes::{
            algorithms::{Ciphersuite, Scheme, CL03},
            generics::{BlindSignature, Commitment, PoKSignature, ZKPoK},
        },
        utils::message::cl03_message::CL03Message,
    };
    use digest::Digest;

    //Proof of knowledge of secrets (ZKPoK) - CL1024-SHA256
    #[test]
    fn zkpok_cl1024_sha256() {
        zkpok::<CL03_CL1024_SHA256>();
    }

    //Signature Proof of Knowledge - CL1024-SHA256
    #[test]
    fn spok_cl1024_sha256() {
        spok::<CL03_CL1024_SHA256>();
    }

    fn zkpok<S: Scheme>()
    where
        S::Ciphersuite: CLCiphersuite,
        <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
    {
        const msgs: &[&str] = &[
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
        ];

        const wrong_msgs: &[&str] = &[
            "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
        ];

        let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
        let a_bases = Bases::generate(cl03_keypair.public_key(), msgs.len());

        let messages: Vec<CL03Message> = msgs
            .iter()
            .map(|&m| {
                CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                    &hex::decode(m).unwrap(),
                )
            })
            .collect();
        let wrong_messages: Vec<CL03Message> = wrong_msgs
            .iter()
            .map(|&m| {
                CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                    &hex::decode(m).unwrap(),
                )
            })
            .collect();

        let unrevealed_message_indexes = [0usize];
        let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(
            &messages,
            cl03_keypair.public_key(),
            &a_bases,
            Some(&unrevealed_message_indexes),
        );
        let wrong_commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(
            &wrong_messages,
            cl03_keypair.public_key(),
            &a_bases,
            Some(&unrevealed_message_indexes),
        );

        let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
            &messages,
            commitment.cl03Commitment(),
            None,
            cl03_keypair.public_key(),
            &a_bases,
            None,
            &unrevealed_message_indexes,
        );

        let valid = zkpok.verify_proof(
            commitment.cl03Commitment(),
            None,
            cl03_keypair.public_key(),
            &a_bases,
            None,
            &unrevealed_message_indexes,
        );

        assert!(valid, "Error! ZKPoK verification should PASS");

        let valid = zkpok.verify_proof(
            wrong_commitment.cl03Commitment(),
            None,
            cl03_keypair.public_key(),
            &a_bases,
            None,
            &unrevealed_message_indexes,
        );

        assert!(!valid, "Error! ZKPok verification should FAIL");

        //Trusted Party Commitment

        let trusted_party_commitment_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(
            None,
            Some(msgs.len().try_into().unwrap()),
        );
        let trusted_party_commitment =
            Commitment::<CL03<S::Ciphersuite>>::commit_with_commitment_pk(
                &messages,
                &trusted_party_commitment_pk,
                Some(&unrevealed_message_indexes),
            );
        let trusted_party_commitment_wrong =
            Commitment::<CL03<S::Ciphersuite>>::commit_with_commitment_pk(
                &wrong_messages,
                &trusted_party_commitment_pk,
                Some(&unrevealed_message_indexes),
            );

        let zkpok2 = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
            &messages,
            commitment.cl03Commitment(),
            Some(trusted_party_commitment.cl03Commitment()),
            cl03_keypair.public_key(),
            &a_bases,
            Some(&trusted_party_commitment_pk),
            &unrevealed_message_indexes,
        );

        let valid = zkpok2.verify_proof(
            commitment.cl03Commitment(),
            Some(trusted_party_commitment.cl03Commitment()),
            cl03_keypair.public_key(),
            &a_bases,
            Some(&trusted_party_commitment_pk),
            &unrevealed_message_indexes,
        );

        assert!(valid, "Error! ZKPoK verification should PASS");

        let zkpok2_wrong_tp_commitment = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
            &messages,
            commitment.cl03Commitment(),
            Some(trusted_party_commitment_wrong.cl03Commitment()),
            cl03_keypair.public_key(),
            &a_bases,
            Some(&trusted_party_commitment_pk),
            &unrevealed_message_indexes,
        );

        let valid = zkpok2_wrong_tp_commitment.verify_proof(
            commitment.cl03Commitment(),
            Some(trusted_party_commitment.cl03Commitment()),
            cl03_keypair.public_key(),
            &a_bases,
            Some(&trusted_party_commitment_pk),
            &unrevealed_message_indexes,
        );

        assert!(!valid, "Error! ZKPoK verification should FAIL");
    }

    pub(crate) fn spok<S: Scheme>()
    where
        S::Ciphersuite: CLCiphersuite,
        <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
    {
        const msgs: &[&str] = &[
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
            "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
        ];
        // const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
        const wrong_msgs: &[&str] = &[
            "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
            "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03",
            "7872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f04",
        ];

        let n_attr = msgs.len();
        let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
        let a_bases = Bases::generate(cl03_keypair.public_key(), n_attr);

        let messages: Vec<CL03Message> = msgs
            .iter()
            .map(|&m| {
                CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                    &hex::decode(m).unwrap(),
                )
            })
            .collect();
        // let msg_intger = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(&hex::decode(msg).unwrap());
        // let messages = [msg_intger.clone()];
        let wrong_messages: Vec<CL03Message> = wrong_msgs
            .iter()
            .map(|&m| {
                CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
                    &hex::decode(m).unwrap(),
                )
            })
            .collect();

        let unrevealed_message_indexes = [0usize];
        let revealed_message_indexes = [1usize, 2usize];
        let revealed_messages: Vec<CL03Message> = messages
            .iter()
            .enumerate()
            .filter(|&(i, _)| revealed_message_indexes.contains(&i))
            .map(|(_, m)| m.clone())
            .collect();
        let revealed_messages_wrong: Vec<CL03Message> = wrong_messages
            .iter()
            .enumerate()
            .filter(|&(i, _)| revealed_message_indexes.contains(&i))
            .map(|(_, m)| m.clone())
            .collect();

        let commitment = Commitment::<CL03<S::Ciphersuite>>::commit_with_pk(
            &messages,
            cl03_keypair.public_key(),
            &a_bases,
            Some(&unrevealed_message_indexes),
        );

        let zkpok = ZKPoK::<CL03<S::Ciphersuite>>::generate_proof(
            &messages,
            commitment.cl03Commitment(),
            None,
            cl03_keypair.public_key(),
            &a_bases,
            None,
            &unrevealed_message_indexes,
        );

        let blind_signature = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(
            cl03_keypair.public_key(),
            cl03_keypair.private_key(),
            &a_bases,
            &zkpok,
            Some(&revealed_messages),
            commitment.cl03Commitment(),
            None,
            None,
            &unrevealed_message_indexes,
            Some(&revealed_message_indexes),
        );
        let unblided_signature = blind_signature.unblind_sign(&commitment);
        let verify =
            unblided_signature.verify_multiattr(cl03_keypair.public_key(), &a_bases, &messages);

        assert!(
            verify,
            "Error! The unblided signature verification should PASS!"
        );

        let blind_signature_wrong = BlindSignature::<CL03<S::Ciphersuite>>::blind_sign(
            cl03_keypair.public_key(),
            cl03_keypair.private_key(),
            &a_bases,
            &zkpok,
            Some(&revealed_messages_wrong),
            commitment.cl03Commitment(),
            None,
            None,
            &unrevealed_message_indexes,
            Some(&revealed_message_indexes),
        );
        let unblided_signature_wrong = blind_signature_wrong.unblind_sign(&commitment);
        let verify = unblided_signature_wrong.verify_multiattr(
            cl03_keypair.public_key(),
            &a_bases,
            &messages,
        );

        assert!(
            !verify,
            "Error! The unblinded signature verification SHOULD FAIL!"
        );

        let commitment_pk = CL03CommitmentPublicKey::generate::<S::Ciphersuite>(
            Some(cl03_keypair.public_key().N.clone()),
            Some(n_attr),
        );

        let signature_pok = PoKSignature::<CL03<S::Ciphersuite>>::proof_gen(
            unblided_signature.cl03Signature(),
            &commitment_pk,
            cl03_keypair.public_key(),
            &a_bases,
            &messages,
            &unrevealed_message_indexes,
        );
        let valid_proof = signature_pok.proof_verify(
            &commitment_pk,
            cl03_keypair.public_key(),
            &a_bases,
            &revealed_messages,
            &unrevealed_message_indexes,
            n_attr,
        );

        assert!(
            valid_proof,
            "Error! The signature proof of knowledge should PASS!"
        );

        let signature_pok = PoKSignature::<CL03<S::Ciphersuite>>::proof_gen(
            unblided_signature.cl03Signature(),
            &commitment_pk,
            cl03_keypair.public_key(),
            &a_bases,
            &messages,
            &unrevealed_message_indexes,
        );
        let valid_proof = signature_pok.proof_verify(
            &commitment_pk,
            cl03_keypair.public_key(),
            &a_bases,
            &revealed_messages_wrong,
            &unrevealed_message_indexes,
            n_attr,
        );

        assert!(
            !valid_proof,
            "Error! The signature proof of knowledge should FAIL!"
        );
    }
}
