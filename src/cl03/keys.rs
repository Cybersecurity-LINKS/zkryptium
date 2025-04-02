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

use crate::{
    cl03::ciphersuites::CLCiphersuite,
    keys::{
        pair::KeyPair,
        traits::{PrivateKey, PublicKey},
    },
    schemes::algorithms::{Scheme, CL03},
    utils::random::{random_number, random_prime, random_qr},
};
use rug::{
    integer::{IsPrime, Order},
    Integer,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, PartialOrd, Eq, Hash, Debug, Ord, Serialize, Deserialize)]
pub struct CL03PublicKey {
    pub N: Integer,
    pub b: Integer,
    pub c: Integer,
}

impl CL03PublicKey {
    pub fn new(N: Integer, b: Integer, c: Integer) -> Self {
        Self { N, b, c }
    }

    pub fn to_bytes<S: Scheme>(&self) -> Vec<u8>
    where
        S: Scheme,
        S::Ciphersuite: CLCiphersuite,
    {
        let mut bytes: Vec<u8> = Vec::new();
        let mut N_digits = vec![0u8; <S as Scheme>::Ciphersuite::ln as usize];
        let mut b_digits = vec![0u8; <S as Scheme>::Ciphersuite::ln as usize];
        let mut c_digits = vec![0u8; <S as Scheme>::Ciphersuite::ln as usize];
        self.N.write_digits(&mut N_digits, Order::MsfBe);
        self.b.write_digits(&mut b_digits, Order::MsfBe);
        self.c.write_digits(&mut c_digits, Order::MsfBe);
        bytes.extend_from_slice(&N_digits);
        bytes.extend_from_slice(&b_digits);
        bytes.extend_from_slice(&c_digits);

        bytes
    }

    pub fn from_bytes<S: Scheme>(bytes: &[u8]) -> Self
    where
        S: Scheme,
        S::Ciphersuite: CLCiphersuite,
    {
        // let delta: usize = (<S as Scheme>::Ciphersuite::SECPARAM as usize) / 8usize + 1usize;
        let N_len = <S as Scheme>::Ciphersuite::ln as usize;

        let len = bytes.len();
        if len < 3 * N_len || (len - (3 * N_len)) % (N_len) != 0 {
            panic!("Invalid number of bytes submitted!");
        }

        let N = Integer::from_digits(&bytes[0usize..N_len], Order::MsfBe);
        let b = Integer::from_digits(&bytes[N_len..2 * N_len], Order::MsfBe);
        let c = Integer::from_digits(&bytes[2 * N_len..3 * N_len], Order::MsfBe);

        Self { N, b, c }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct CL03SecretKey {
    pub p: Integer,
    pub q: Integer,
}

impl CL03SecretKey {
    pub fn new(p: Integer, q: Integer) -> Self {
        Self { p, q }
    }

    pub fn to_bytes<S>(&self) -> Vec<u8>
    where
        S: Scheme,
        S::Ciphersuite: CLCiphersuite,
    {
        let mut bytes: Vec<u8> = Vec::new();
        let mut p_digits =
            vec![0u8; (<S as Scheme>::Ciphersuite::SECPARAM as usize) / 8usize + 1usize];
        let mut q_digits =
            vec![0u8; (<S as Scheme>::Ciphersuite::SECPARAM as usize) / 8usize + 1usize];
        self.p.write_digits(&mut p_digits, Order::MsfBe);
        self.q.write_digits(&mut q_digits, Order::MsfBe);
        bytes.extend_from_slice(&p_digits);
        bytes.extend_from_slice(&q_digits);
        bytes
    }

    pub fn from_bytes<S: Scheme>(bytes: &[u8]) -> Self
    where
        S: Scheme,
        S::Ciphersuite: CLCiphersuite,
    {
        let delta = (<S as Scheme>::Ciphersuite::SECPARAM as usize) / 8usize + 1usize;
        let p = Integer::from_digits(&bytes[0usize..delta], Order::MsfBe);
        let q = Integer::from_digits(&bytes[delta..(2 * delta)], Order::MsfBe);

        Self { p, q }
    }
}

impl PublicKey for CL03PublicKey {
    type Output = [u8; 512];
    // type Params = (Integer, Integer, Integer, Vec<(Integer, bool)>);
    fn encode(&self) -> String {
        todo!()
    }

    fn to_bytes(&self) -> Self::Output {
        todo!()
    }

    // fn get_params(&self) -> (Integer, Integer, Integer, Vec<(Integer, bool)>) {
    //     (self.N.clone(), self.b.clone(), self.c.clone(), self.a_bases.clone())
    // }
}

impl PrivateKey for CL03SecretKey {
    type Output = [u8; 512];
    fn to_bytes(&self) -> Self::Output {
        todo!()
    }

    fn encode(&self) -> String {
        todo!()
    }
}

impl<CS: CLCiphersuite> KeyPair<CL03<CS>> {
    pub fn generate() -> Self {
        let n = CS::SECPARAM;
        let mut pprime;
        let mut p;
        let preps = 3 + 24;         // "is_probably_prime" subtracts 24 from reps.
        let qreps = CS::QSEC + 24;  // "is_probably_prime" subtracts 24 from reps.
        // Rationale is: according to NIST FIPS 186-4 Appendix C, table C1 (Minimum MR iterations
        // for DSA key generation) shows that the necessary amount of iterations is half the
        // security bits. Function "is_probably_prime" internally executes "reps - 24" rounds of MR
        // testing.
        loop {
            pprime = random_prime(n);
            p = Integer::from(2) * pprime + Integer::from(1);
            if p.is_probably_prime(preps) != IsPrime::No {
                break;
            }
        }

        let mut qprime;
        let mut q;
        loop {
            qprime = random_prime(n);
            q = Integer::from(2) * qprime + Integer::from(1);
            if p != q && q.is_probably_prime(qreps) != IsPrime::No {
                break;
            }
        }

        let N = p.clone() * q.clone();

        // let mut a_bases: Vec<Integer> = Vec::new();

        // let n_attr = n_attributes.unwrap_or(1);
        // for _i in 0..n_attr {
        //     let a = random_qr(&N);
        //     a_bases.push(a);
        // }

        let b = random_qr(&N);
        let c = random_qr(&N);

        let pk = CL03PublicKey::new(N, b, c);
        let sk = CL03SecretKey::new(p, q);

        Self {
            public: pk,
            private: sk,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct CL03CommitmentPublicKey {
    pub N: Integer,
    pub h: Integer,
    pub g_bases: Vec<Integer>,
}

impl CL03CommitmentPublicKey {
    //verifier_pk -> N = issuer_pk.N
    //trusted_party_pk -> N = None
    pub fn generate<CS: CLCiphersuite>(N: Option<Integer>, n_attributes: Option<usize>) -> Self {
        let n = CS::SECPARAM; //SECPARAM
        let preps = 3 + 24;         // "is_probably_prime" subtracts 24 from reps.
        let qreps = CS::QSEC + 24; // "is_probably_prime" subtracts 24 from reps.
        let n_attributes = n_attributes.unwrap_or(1);
        let N = N.unwrap_or_else(|| {
            let mut pprime;
            let mut p;
            loop {
                // println!("{} INT", p);
                // let digits = p.to_digits::<u8>(Order::MsfBe);
                // let bignum = BigUint::from_bytes_be(&digits);
                // println!("{} BIGNUM", bignum);
                pprime = random_prime(n);
                p = Integer::from(2) * pprime + Integer::from(1);

                if p.is_probably_prime(preps) != IsPrime::No {
                    break;
                }
            }

            let mut qprime;
            let mut q;
            loop {
                // println!("{} INT", p);
                // let digits = p.to_digits::<u8>(Order::MsfBe);
                // let bignum = BigUint::from_bytes_be(&digits);
                // println!("{} BIGNUM", bignum);
                qprime = random_prime(n);
                q = Integer::from(2) * qprime + Integer::from(1);
                if p != q && q.is_probably_prime(qreps) != IsPrime::No {
                    break;
                }
            }

            let N = p.clone() * q.clone();
            N
        });

        let h = random_qr(&N);

        let mut g_bases: Vec<Integer> = Vec::new();

        for _i in 0..n_attributes {
            let mut f = random_number(N.clone());
            let mut g_i = Integer::from(h.pow_mod_ref(&f, &N).unwrap());

            loop {
                if ((g_i > Integer::from(1))
                    && (Integer::from(g_i.gcd_ref(&N)) == Integer::from(1)))
                    == false
                {
                    f = random_number(N.clone());
                    g_i = Integer::from(h.pow_mod_ref(&f, &N).unwrap());
                } else {
                    break;
                }
            }
            g_bases.push(g_i);
        }

        CL03CommitmentPublicKey {
            N: N,
            h: h,
            g_bases: g_bases,
        }
    }
}
