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
    bases::Bases,
    ciphersuites::CLCiphersuite,
    commitment::CL03Commitment,
    keys::{CL03CommitmentPublicKey, CL03PublicKey},
    signature::CL03Signature,
};
use crate::{
    schemes::algorithms::CL03,
    schemes::generics::Commitment,
    utils::{message::cl03_message::CL03Message, random::random_bits, util::cl03_utils::divm},
};
use digest::Digest;
use rug::{integer::Order, Complete, Integer};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct NISP2Commitments {
    challenge: Integer,
    d: Vec<Integer>,
    d_1: Integer,
    d_2: Integer,
}

impl NISP2Commitments {
    /* Generation of the proof related to two commitments (C1 and C2) (generate proof that C1 is a commitment to the same secrets as C2) */
    pub(crate) fn nisp2_generate_proof_MultiSecrets<CS>(
        messages: &[CL03Message],
        c1: &CL03Commitment,
        c2: &CL03Commitment,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        commitment_pk: &CL03CommitmentPublicKey,
        unrevealed_message_indexes: &[usize],
    ) -> Self
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest,
    {
        let n_attr = messages.len();

        if a_bases.0.len() < n_attr && n_attr < commitment_pk.g_bases.len() {
            panic!("Not enough a_bases OR g_bases for the number of attributes");
        }

        let h1 = &signer_pk.b;
        let n1 = &signer_pk.N;
        let h2 = &commitment_pk.h;
        let n2 = &commitment_pk.N;

        // Initialize multiple random values, equivalent to secrets m_i and stored in a list
        let mut omega: Vec<Integer> = Vec::new();
        for _i in unrevealed_message_indexes {
            omega.push(random_bits(CS::lm));
        }

        let mu_1 = random_bits(CS::ln);
        let mu_2 = random_bits(CS::ln);

        let mut w_1 = Integer::from(1);
        let mut w_2 = Integer::from(1);
        let mut idx = 0usize;

        for i in unrevealed_message_indexes {
            w_1 = w_1
                * (Integer::from(
                    a_bases
                        .0
                        .get(*i)
                        .expect("unrevealed_message_indexes not valid (overflow)")
                        .pow_mod_ref(&omega[idx], n1)
                        .unwrap(),
                ));
            w_2 = w_2
                * (Integer::from(
                    commitment_pk
                        .g_bases
                        .get(*i)
                        .expect("unrevealed_message_indexes not valid (overflow)")
                        .pow_mod_ref(&omega[idx], n2)
                        .unwrap(),
                ));
            idx = idx + 1;
        }
        w_1 = (w_1 * Integer::from(h1.pow_mod_ref(&mu_1, n1).unwrap())) % n1;
        w_2 = (w_2 * Integer::from(h2.pow_mod_ref(&mu_2, n2).unwrap())) % n2;

        let str = w_1.to_string() + &w_2.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let mut d: Vec<Integer> = Vec::new();
        let mut idx = 0usize;

        for i in unrevealed_message_indexes {
            d.push(
                (&omega[idx]
                    + &challenge
                        * &messages
                            .get(*i)
                            .expect("unrevealed_message_indexes not valid (overflow)")
                            .value)
                    .complete(),
            );
            idx = idx + 1;
        }

        let d_1 = mu_1 + &challenge * &c1.randomness;
        let d_2 = mu_2 + &challenge * &c2.randomness;

        Self {
            challenge,
            d,
            d_1,
            d_2,
        }
    }

    /* Verification of the proof for two commitments (C1 and C2) */
    pub(crate) fn nisp2_verify_proof_MultiSecrets<CS>(
        &self,
        c1: &CL03Commitment,
        c2: &CL03Commitment,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        commitment_pk: &CL03CommitmentPublicKey,
        unrevealed_message_indexes: &[usize],
    ) -> bool
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest,
    {
        let h1 = &signer_pk.b;
        let n1 = &signer_pk.N;
        let h2 = &commitment_pk.h;
        let n2 = &commitment_pk.N;

        let Self {
            challenge,
            d,
            d_1,
            d_2,
        } = self;

        let inv_C1 = Integer::from(
            c1.value
                .pow_mod_ref(&(-Integer::from(1) * challenge), n1)
                .unwrap(),
        );
        let inv_C2 = Integer::from(
            c2.value
                .pow_mod_ref(&(-Integer::from(1) * challenge), n2)
                .unwrap(),
        );

        let mut lhs = Integer::from(1);
        let mut rhs = Integer::from(1);
        let mut idx = 0usize;

        for i in unrevealed_message_indexes {
            lhs = lhs
                * Integer::from(
                    a_bases
                        .0
                        .get(*i)
                        .expect("unrevealed_message_indexes not valid (overflow)")
                        .pow_mod_ref(&d[idx], n1)
                        .unwrap(),
                );
            rhs = rhs
                * Integer::from(
                    commitment_pk
                        .g_bases
                        .get(*i)
                        .expect("unrevealed_message_indexes not valid (overflow)")
                        .pow_mod_ref(&d[idx], n2)
                        .unwrap(),
                );
            idx += 1;
        }
        // lhs = ((lhs * powmod(h1, d_1, n1)) * inv_C1) % n1
        // rhs = ((rhs * powmod(h2, d_2, n2)) * inv_C2) % n2
        lhs = ((lhs * Integer::from(h1.pow_mod_ref(d_1, n1).unwrap())) * inv_C1) % n1;
        rhs = ((rhs * Integer::from(h2.pow_mod_ref(d_2, n2).unwrap())) * inv_C2) % n2;

        let str = lhs.to_string() + &rhs.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str);
        let output = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        challenge == &output
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct NISPSecrets {
    t: Integer,
    s1: Integer,
    s2: Integer,
}

impl NISPSecrets {
    pub(crate) fn nisp2sec_generate_proof<CS>(
        message: &CL03Message,
        commitment: &CL03Commitment,
        g1: &Integer,
        h1: &Integer,
        n1: &Integer,
    ) -> Self
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest,
    {
        let r1 = random_bits(CS::lm);
        let r2 = random_bits(CS::ln);

        let t = (Integer::from(g1.pow_mod_ref(&r1, &n1).unwrap())
            * Integer::from(h1.pow_mod_ref(&r2, &n1).unwrap()))
            % n1;
        let str_input =
            g1.to_string() + &h1.to_string() + &commitment.value.to_string() + &t.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str_input);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let s1 = r1 + (&challenge * &message.value);
        let s2 = r2 + (&challenge * &commitment.randomness);

        Self { t, s1, s2 }
    }

    pub(crate) fn nisp2sec_verify_proof<CS>(
        &self,
        commitment: &CL03Commitment,
        g1: &Integer,
        h1: &Integer,
        n1: &Integer,
    ) -> bool
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest,
    {
        let Self { t, s1, s2 } = self;
        let lhs = (Integer::from(g1.pow_mod_ref(s1, &n1).unwrap())
            * Integer::from(h1.pow_mod_ref(s2, &n1).unwrap()))
            % n1;
        let str_input =
            g1.to_string() + &h1.to_string() + &commitment.value.to_string() + &t.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str_input);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let rhs = (t * Integer::from(commitment.value.pow_mod_ref(&challenge, &n1).unwrap())) % n1;

        lhs == rhs
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct NISPMultiSecrets {
    t: Integer,
    s1: Vec<Integer>,
    s2: Integer,
}

impl NISPMultiSecrets {
    /* Generation of the proof related to multiple secrets (x and r) */
    pub(crate) fn nispMultiSecrets_generate_proof<CS>(
        messages: &[CL03Message],
        commitment: &CL03Commitment,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        unrevealed_message_indexes: Option<&[usize]>,
    ) -> Self
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest,
    {
        let mut unrevealed_message_indexes = unrevealed_message_indexes.unwrap_or(&[0]);
        // Initialize multiple random values, equivalent to secrets m_i and stored in a list

        if messages.len() == 1 {
            unrevealed_message_indexes = &[0];
        }

        let mut r1: Vec<Integer> = Vec::new();
        for _ in unrevealed_message_indexes {
            r1.push(random_bits(CS::lm));
        }

        let r2 = random_bits(CS::ln);

        let h1 = &signer_pk.b;
        let n1 = &signer_pk.N;

        let mut t = Integer::from(1);
        let mut str_input = String::from("");
        let mut idx = 0usize;
        for i in unrevealed_message_indexes {
            t = t * Integer::from(
                a_bases
                    .0
                    .get(*i)
                    .expect("unrevealed_message_indexes not valid (overflow)")
                    .pow_mod_ref(&r1[idx], n1)
                    .unwrap(),
            );
            str_input = str_input + &a_bases.0[*i].to_string();
            idx += 1;
        }
        t = (t * Integer::from(h1.pow_mod_ref(&r2, n1).unwrap())) % n1;

        str_input = str_input + &h1.to_string() + &commitment.value.to_string() + &t.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str_input);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let mut s1: Vec<Integer> = Vec::new();
        idx = 0usize;

        for i in unrevealed_message_indexes {
            s1.push(
                (&r1[idx]
                    + &challenge
                        * &messages
                            .get(*i)
                            .expect("unrevealed_message_indexes not valid (overflow)")
                            .value)
                    .complete(),
            );
            idx += 1;
        }
        let s2 = r2 + (challenge * &commitment.randomness);

        Self { t, s1, s2 }

        //NOTE: s1 is a list with number_of_secrets values
    }

    pub(crate) fn nispMultiSecrets_verify_proof<CS>(
        &self,
        commitment: &CL03Commitment,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        unrevealed_message_indexes: Option<&[usize]>,
    ) -> bool
    where
        CS: CLCiphersuite,
        CS::HashAlg: Digest,
    {
        let unrevealed_message_indexes = unrevealed_message_indexes.unwrap_or(&[0]);

        let h1 = &signer_pk.b;
        let n1 = &signer_pk.N;
        let Self { t, s1, s2 } = self;

        if unrevealed_message_indexes.len() != s1.len() {
            panic!("unrevealed_message_indexes not valid");
        }

        let mut lhs = Integer::from(1);
        let mut str_input = String::from("");
        let mut idx = 0usize;

        for i in unrevealed_message_indexes {
            lhs = lhs
                * Integer::from(
                    a_bases
                        .0
                        .get(*i)
                        .expect("unrevealed_message_indexes not valid (overflow)")
                        .pow_mod_ref(&s1[idx], n1)
                        .unwrap(),
                );
            str_input = str_input + &a_bases.0[*i].to_string();
            idx += 1;
        }
        lhs = (lhs * Integer::from(h1.pow_mod_ref(&s2, n1).unwrap())) % n1;
        str_input = str_input + &h1.to_string() + &commitment.value.to_string() + &t.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str_input);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let rhs = (t * Integer::from(commitment.value.pow_mod_ref(&challenge, n1).unwrap())) % n1;

        lhs == rhs
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub(crate) struct NISPSignaturePoK {
    pub(crate) challenge: Integer,
    pub(crate) s_1: Integer,
    pub(crate) s_2: Integer,
    pub(crate) s_3: Integer,
    pub(crate) s_4: Integer,
    pub(crate) s_5: Vec<Integer>,
    pub(crate) s_6: Integer,
    pub(crate) s_7: Integer,
    pub(crate) s_8: Integer,
    pub(crate) s_9: Integer,
    pub(crate) Cx: CL03Commitment,
    pub(crate) Cv: CL03Commitment,
    pub(crate) Cw: CL03Commitment,
    pub(crate) Ce: CL03Commitment,
}

impl NISPSignaturePoK {
    pub(crate) fn nisp5_MultiAttr_generate_proof<CS: CLCiphersuite>(
        signature: &CL03Signature,
        commitment_pk: &CL03CommitmentPublicKey,
        signer_pk: &CL03PublicKey,
        a_bases: &Bases,
        messages: &[CL03Message],
        unrevealed_message_indexes: &[usize],
    ) -> NISPSignaturePoK
    where
        CS::HashAlg: Digest,
    {
        let n_attr = messages.len();

        if a_bases.0.len() < n_attr && commitment_pk.g_bases.len() < n_attr {
            panic!("Not enough a_bases OR g_bases for the number of attributes");
        }

        let C_Cx = Commitment::<CL03<CS>>::commit_with_commitment_pk(messages, commitment_pk, None);
        let (_Cx, rx) = (C_Cx.value(), C_Cx.randomness());

        let C_Cv = Commitment::<CL03<CS>>::commit_v(&signature.v, commitment_pk);
        let (Cv, w) = (C_Cv.value(), C_Cv.randomness());

        let C_Cw = Commitment::<CL03<CS>>::commit_with_commitment_pk(
            &[CL03Message::new(w.clone())],
            commitment_pk,
            None,
        );
        let (Cw, rw) = (C_Cw.value(), C_Cw.randomness());

        let C_Ce = Commitment::<CL03<CS>>::commit_with_commitment_pk(
            &[CL03Message::new(signature.e.clone())],
            commitment_pk,
            None,
        );
        let (_Ce, re) = (C_Ce.value(), C_Ce.randomness());

        let (r_1, r_2, r_3, r_4, r_6, r_7, r_8, r_9) = (
            random_bits(CS::ln),
            random_bits(CS::ln),
            random_bits(CS::ln),
            random_bits(CS::ln),
            random_bits(CS::ln),
            random_bits(CS::ln),
            random_bits(CS::ln),
            random_bits(CS::ln),
        );

        let mut r_5: Vec<Integer> = Vec::new();

        for i in 0..n_attr {
            if unrevealed_message_indexes.contains(&i) {
                r_5.push(random_bits(CS::ln));
            } else {
                r_5.push(messages.get(i).expect("index overflow").value.clone());
            }
        }

        let N = &signer_pk.N;

        let mut t_Cx = Integer::from(1);
        for i in 0..n_attr {
            t_Cx = t_Cx * Integer::from(a_bases.0[i].pow_mod_ref(&r_5[i], N).unwrap())
        }

        t_Cx = t_Cx % N;

        let t_1 = (Integer::from(Cv.pow_mod_ref(&r_4, N).unwrap())
            * divm(&Integer::from(1), &t_Cx, N)
            * Integer::from(
                divm(&Integer::from(1), &signer_pk.b, N)
                    .pow_mod_ref(&r_6, N)
                    .unwrap(),
            )
            * Integer::from(
                divm(&Integer::from(1), &commitment_pk.g_bases[0], N)
                    .pow_mod_ref(&r_8, N)
                    .unwrap(),
            ))
            % N;
        let t_2 = (Integer::from(commitment_pk.g_bases[0].pow_mod_ref(&r_7, N).unwrap())
            * Integer::from(commitment_pk.h.pow_mod_ref(&r_1, N).unwrap()))
            % N;
        let t_3 = (Integer::from(Cw.pow_mod_ref(&r_4, N).unwrap())
            * Integer::from(
                divm(&Integer::from(1), &commitment_pk.g_bases[0], N)
                    .pow_mod_ref(&r_8, N)
                    .unwrap(),
            )
            * Integer::from(
                divm(&Integer::from(1), &commitment_pk.h, N)
                    .pow_mod_ref(&r_2, N)
                    .unwrap(),
            ))
            % N;

        let mut t_4 = Integer::from(1);
        for i in 0..n_attr {
            t_4 = t_4 * Integer::from(commitment_pk.g_bases[i].pow_mod_ref(&r_5[i], N).unwrap());
        }
        t_4 = (t_4 * Integer::from(commitment_pk.h.pow_mod_ref(&r_3, N).unwrap())) % N;

        let t_5 = (Integer::from(commitment_pk.g_bases[0].pow_mod_ref(&r_4, N).unwrap())
            * Integer::from(commitment_pk.h.pow_mod_ref(&r_9, N).unwrap()))
            % N;
        let str = t_1.to_string()
            + &t_2.to_string()
            + &t_3.to_string()
            + &t_4.to_string()
            + &t_5.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        let s_1 = r_1 + rw * &challenge;
        let s_2 = r_2 + rw * signature.e.clone() * &challenge;
        let s_3 = r_3 + rx * &challenge;
        let s_4 = r_4 + signature.e.clone() * &challenge;
        let mut s_5: Vec<Integer> = Vec::new();
        for i in unrevealed_message_indexes {
            let si = r_5
                .get(*i)
                .expect("unrevealed_message_indexes not valid (overflow)")
                + messages
                    .get(*i)
                    .expect("unrevealed_message_indexes not valid (overflow)")
                    .value
                    .clone()
                    * &challenge;
            s_5.push(si);
        }

        let s_6 = r_6 + signature.s.clone() * &challenge;
        let s_7 = r_7 + w * &challenge;
        let s_8 = r_8 + w * signature.e.clone() * &challenge;
        let s_9 = r_9 + re * &challenge;

        NISPSignaturePoK {
            challenge,
            s_1,
            s_2,
            s_3,
            s_4,
            s_5,
            s_6,
            s_7,
            s_8,
            s_9,
            Cx: C_Cx.cl03Commitment().clone(),
            Cv: C_Cv.cl03Commitment().clone(),
            Cw: C_Cw.cl03Commitment().clone(),
            Ce: C_Ce.cl03Commitment().clone(),
        }
    }

    pub(crate) fn nisp5_MultiAttr_verify_proof<CS: CLCiphersuite>(
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
        if a_bases.0.len() < n_signed_messages && commitment_pk.g_bases.len() < n_signed_messages {
            panic!("Not enough a_bases OR g_bases for the number of attributes");
        }

        let mut t_Cx = Integer::from(1);
        let N = &signer_pk.N;
        let mut idx: usize = 0;
        let mut idx_revealed_msgs: usize = 0;

        for i in 0..n_signed_messages {
            if unrevealed_message_indexes.contains(&i) {
                t_Cx = t_Cx * Integer::from(a_bases.0[i].pow_mod_ref(&self.s_5[idx], N).unwrap());
                idx += 1;
            } else {
                let mi = &messages
                    .get(idx_revealed_msgs)
                    .expect("index overflow!")
                    .value;
                let val = mi + (mi * &self.challenge).complete();
                t_Cx = t_Cx * Integer::from(a_bases.0[i].pow_mod_ref(&val, N).unwrap());
                idx_revealed_msgs += 1;
            }
        }
        t_Cx = t_Cx % N;

        let input1 = (Integer::from(self.Cv.value.pow_mod_ref(&self.s_4, N).unwrap())
            * divm(&Integer::from(1), &t_Cx, N)
            * Integer::from(
                divm(&Integer::from(1), &signer_pk.b, N)
                    .pow_mod_ref(&self.s_6, N)
                    .unwrap(),
            )
            * Integer::from(
                divm(&Integer::from(1), &commitment_pk.g_bases[0], N)
                    .pow_mod_ref(&self.s_8, N)
                    .unwrap(),
            )
            * Integer::from(
                signer_pk
                    .c
                    .pow_mod_ref(&(Integer::from(-1) * &self.challenge), N)
                    .unwrap(),
            ))
            % N;
        let input2 = (Integer::from(commitment_pk.g_bases[0].pow_mod_ref(&self.s_7, N).unwrap())
            * Integer::from(commitment_pk.h.pow_mod_ref(&self.s_1, N).unwrap())
            * Integer::from(
                self.Cw
                    .value
                    .pow_mod_ref(&(Integer::from(-1) * &self.challenge), N)
                    .unwrap(),
            ))
            % N;
        let input3 = (Integer::from(self.Cw.value.pow_mod_ref(&self.s_4, N).unwrap())
            * Integer::from(
                divm(&Integer::from(1), &commitment_pk.g_bases[0], N)
                    .pow_mod_ref(&self.s_8, N)
                    .unwrap(),
            )
            * Integer::from(
                divm(&Integer::from(1), &commitment_pk.h, N)
                    .pow_mod_ref(&self.s_2, N)
                    .unwrap(),
            ))
            % N;

        let mut input4 = Integer::from(1);
        let mut idx: usize = 0;
        let mut idx_revealed_msgs: usize = 0;

        for i in 0..n_signed_messages {
            if unrevealed_message_indexes.contains(&i) {
                input4 = input4
                    * Integer::from(
                        commitment_pk.g_bases[i]
                            .pow_mod_ref(&self.s_5[idx], N)
                            .unwrap(),
                    );
                idx += 1;
            } else {
                let mi = &messages
                    .get(idx_revealed_msgs)
                    .expect("index overflow")
                    .value;
                let val = mi + (mi * &self.challenge).complete();
                input4 =
                    input4 * Integer::from(commitment_pk.g_bases[i].pow_mod_ref(&val, N).unwrap());
                idx_revealed_msgs += 1;
            }
        }

        input4 = (input4
            * Integer::from(commitment_pk.h.pow_mod_ref(&self.s_3, N).unwrap())
            * Integer::from(
                self.Cx
                    .value
                    .pow_mod_ref(&(Integer::from(-1) * &self.challenge), N)
                    .unwrap(),
            ))
            % N;

        let input5 = (Integer::from(commitment_pk.g_bases[0].pow_mod_ref(&self.s_4, N).unwrap())
            * Integer::from(commitment_pk.h.pow_mod_ref(&self.s_9, N).unwrap())
            * Integer::from(
                self.Ce
                    .value
                    .pow_mod_ref(&(Integer::from(-1) * &self.challenge), N)
                    .unwrap(),
            ))
            % N;

        let str = input1.to_string()
            + &input2.to_string()
            + &input3.to_string()
            + &input4.to_string()
            + &input5.to_string();
        let hash = <CS::HashAlg as Digest>::digest(str);
        let challenge = Integer::from_digits(hash.as_slice(), Order::MsfBe);

        challenge == self.challenge
    }
}
