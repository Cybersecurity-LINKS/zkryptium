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
                gi,
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
                    gi,
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
        // Input-shape checks: the proof comes from the Prover, it must not make us panic.
        // Revealed messages outside [0, 2^lm) are rejected: from a signature on m_i the Prover
        // can derive one on m_i + k*e (CL03-11).
        let U = unrevealed_message_indexes.len();
        if !messages.iter().all(|m| m.is_in_range::<CS>())
            || CLSPoK.proofs_commited_mi.len() != U
            || CLSPoK.range_proofs_commited_mi.len() != U
            || commitment_pk.g_bases.is_empty()
            || unrevealed_message_indexes.iter().any(|&i| i >= commitment_pk.g_bases.len())
        {
            return false;
        }
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
                for (idx, i) in unrevealed_message_indexes.iter().enumerate() {
                    // Lengths and indexes checked above.
                    let gi = &commitment_pk.g_bases[*i];
                    let ProofOfValue {
                        value: proof_mi,
                        commitment: cmi,
                    } = &CLSPoK.proofs_commited_mi[idx];

                    let boolean_proof_mi = proof_mi.nisp2sec_verify_proof::<CS>(
                        cmi,
                        gi,
                        &commitment_pk.h,
                        &commitment_pk.N,
                    );
                    if !boolean_proof_mi {
                        return false;
                    }

                    let boolean_rproofs_mi = CLSPoK.range_proofs_commited_mi[idx]
                        .verify::<CS::HashAlg>(
                            gi,
                            &commitment_pk.h,
                            &commitment_pk.N,
                            &min_x,
                            &max_x,
                        );
                    if !boolean_rproofs_mi {
                        return false;
                    }
                }
            } else {
                return false;
            }
        } else {
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

/// The commitment computed by a trusted party on the same secrets, with the public key it
/// was computed with. The two values are only meaningful together: [`ZKPoK::generate_proof`]
/// then also proves that the Prover commitment and the trusted one hide the same secrets, and
/// [`ZKPoK::verify_proof`] requires that proof.
#[derive(Clone, Copy, Debug)]
pub struct CL03TrustedCommitment<'a> {
    /// The trusted party commitment.
    pub commitment: &'a CL03Commitment,
    /// The public key used to compute `commitment`.
    pub commitment_pk: &'a CL03CommitmentPublicKey,
}

impl<CS: CLCiphersuite> ZKPoK<CL03<CS>> {
    pub fn generate_proof(
        messages: &[CL03Message],
        C: &CL03Commitment,
        trusted_commitment: Option<CL03TrustedCommitment<'_>>,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        unrevealed_message_indexes: &[usize],
    ) -> Self
    where
        CS::HashAlg: Digest,
    {
        let proof_C_Ctrusted = trusted_commitment.map(|trusted| {
            NISP2Commitments::nisp2_generate_proof_MultiSecrets::<CS>(
                messages,
                C,
                trusted.commitment,
                signer_pk,
                a_bases,
                trusted.commitment_pk,
                unrevealed_message_indexes,
            )
        });

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
                Commitment::<CL03<CS>>::commit_with_pk(std::slice::from_ref(mi), signer_pk, a_bases, None)
                    .cl03Commitment()
                    .to_owned();
            let proof_mi = NISPSecrets::nisp2sec_generate_proof::<CS>(
                mi,
                &cmi,
                ai,
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
                        ai,
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
        let cr = Commitment::<CL03<CS>>::commit_with_pk(std::slice::from_ref(&r), signer_pk, a_bases, None);
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
            proof_r,
            range_proof_r: rproof_r,
        })
    }

    /// Verifies the proof. It returns `false`, without panicking, when the proof does not
    /// match the inputs: a missing proof for `trusted_commitment`, a different number of
    /// proofs and `unrevealed_message_indexes`, or an index outside `a_bases`.
    pub fn verify_proof(
        &self,
        C: &CL03Commitment,
        trusted_commitment: Option<CL03TrustedCommitment<'_>>,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        unrevealed_message_indexes: &[usize],
    ) -> bool
    where
        CS::HashAlg: Digest,
    {
        let zkpok = self.to_cl03_zkpok();

        // Input-shape checks: the proof comes from the Prover, it must not make us panic.
        let U = unrevealed_message_indexes.len();
        if zkpok.proofs_commited_mi.len() != U || zkpok.range_proofs_mi.len() != U {
            return false;
        }
        if a_bases.0.is_empty() || unrevealed_message_indexes.iter().any(|&i| i >= a_bases.0.len()) {
            return false;
        }

        if let Some(trusted) = trusted_commitment {
            // The Signer asked for the trusted-commitment check: a proof without it is invalid.
            let Some(proof_C_Ctrusted) = &zkpok.proof_C_Ctrusted else {
                return false;
            };
            if !proof_C_Ctrusted.nisp2_verify_proof_MultiSecrets::<CS>(
                C,
                trusted.commitment,
                signer_pk,
                a_bases,
                trusted.commitment_pk,
                unrevealed_message_indexes,
            ) {
                return false;
            }
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
            return false;
        }

        let min_x = Integer::from(0);
        let max_x = Integer::from(2).pow(CS::lm) - 1;

        for (idx, i) in unrevealed_message_indexes.iter().enumerate() {
            // Lengths and indexes checked above.
            let ai = &a_bases.0[*i];
            let proof_mi = &zkpok.proofs_commited_mi[idx];
            let boolean_proof_mi = proof_mi.value.nisp2sec_verify_proof::<CS>(
                &proof_mi.commitment,
                ai,
                &signer_pk.b,
                &signer_pk.N,
            );

            if !boolean_proof_mi {
                return false;
            }
            let rproof_mi = &zkpok.range_proofs_mi[idx];
            let boolean_rproof_mi =
                rproof_mi.verify::<CS::HashAlg>(ai, &signer_pk.b, &signer_pk.N, &min_x, &max_x);
            if !boolean_rproof_mi {
                return false;
            }

        }

        let boolean_proof_r = zkpok.proof_r.value.nisp2sec_verify_proof::<CS>(
            &zkpok.proof_r.commitment,
            &a_bases.0[0],
            &signer_pk.b,
            &signer_pk.N,
        );
        if !boolean_proof_r {
            return false;
        }

        let min_r = Integer::from(0);
        let max_r = Integer::from(2).pow(CS::ln) - 1;
        zkpok.range_proof_r.verify::<CS::HashAlg>(
            &a_bases.0[0],
            &signer_pk.b,
            &signer_pk.N,
            &min_r,
            &max_r,
        )
    }

    pub fn to_cl03_zkpok(&self) -> &CL03ZKPoK {
        match self {
            Self::CL03(inner) => inner,
            _ => panic!("Cannot happen!"),
        }
    }
}

#[cfg(test)]
mod tests;
