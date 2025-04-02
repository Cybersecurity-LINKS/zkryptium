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

use super::range_proof::RangeProof;
use crate::schemes::algorithms::Ciphersuite;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub trait CLCiphersuite: Eq + 'static + Ciphersuite {
    const SECPARAM: u32;
    const QSEC: u32; // NOTE: Miller-Rabin repetitions for primality testing of q prime. (Check NIST-FIPS 186-4, Table C.1, Column 2 (Integer.is_probably_prime runs a lukas test internally and "reps - 24" repetitions of the MR primality test)
    const ln: u32; // NOTE: length of n (i.e. special RSA modulus), ln will be used to generate all randomness and bases for public keys
    const lm: u32; // NOTE: length of each secret attribute in the credential, i.e. x = (m0, m1, ... m(M-1))
    const lin: u32; // NOTE: additional security parameter; both lm and lin set to 256 bits to improve security (i.e. SHA256 will be used here, instead of SHA1)
    const le: u32; // NOTE: length of e (i.e. exponent used in the signature, v ** e)
    const ls: u32; // NOTE: length of s (i.e. random number used in the signature, b ** s)

    // RANGE PROOFS
    const RANGEPROOF_ALG: RangeProof;
    const t: u32;
    const l: u32;
    const s: u32;
    const s1: u32;
    const s2: u32;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL1024Sha256 {}

impl CLCiphersuite for CL1024Sha256 {
    const SECPARAM: u32 = 512;
    const QSEC: u32 = 19; // NOTE: Miller-Rabin repetitions for primality testing of q prime. (Check NIST-FIPS 186-4, Table C.1, Column 2 (Integer.is_probably_prime runs a lukas test internally and "reps - 24" repetitions of the MR primality test)
    const ln: u32 = 2 * Self::SECPARAM; // NOTE: length of n (i.e. special RSA modulus), ln will be used to generate all randomness and bases for public keys
    const lm: u32 = 256; // NOTE: length of each secret attribute in the credential, i.e. x = (m0, m1, ... m(M-1))
    const lin: u32 = 256; // NOTE: additional security parameter; both lm and lin set to 256 bits to improve security (i.e. SHA256 will be used here, instead of SHA1)
    const le: u32 = Self::lm + 2; // NOTE: length of e (i.e. exponent used in the signature, v ** e)
    const ls: u32 = Self::ln + Self::lm + Self::lin; // NOTE: length of s (i.e. random number used in the signature, b ** s)

    //RANGEPROOF
    const RANGEPROOF_ALG: RangeProof = RangeProof::Boudot2000;
    /* Security parameter - Half of the length of the Hash function output
    NOTE: i.e., 2*t bits is the length of the Hash function output.
    The soundness characteristic of the range proof is given by 2**(t−1).
    t = 80: Original value in [Boudot2000], appropriate for SHA-1 - sha160 (i.e. 2*t = 160 bits),
    replaced by t = 128, appropriate for SHA256 (i.e. 2*t = 256). */
    const t: u32 = 128;
    // Security parameter - Zero knowledge property is guaranteed given that 1∕l is negligible
    const l: u32 = 40;
    // Security parameter for the commitment - 2**s  must be negligible
    const s: u32 = 40;
    // Security parameter for the commitment - 2**s1 must be negligible
    const s1: u32 = 40;
    // Security parameter for the commitment - 2**s2 must be negligible
    const s2: u32 = 552;
}

impl Ciphersuite for CL1024Sha256 {
    type HashAlg = Sha256;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL2048Sha256 {}

impl CLCiphersuite for CL2048Sha256 {
    const SECPARAM: u32 = 1024;
    const QSEC: u32 = 27; // NOTE: Miller-Rabin repetitions for primality testing of q prime. (Check NIST-FIPS 186-4, Table C.1, Column 2 (Integer.is_probably_prime runs a lukas test internally and "reps - 24" repetitions of the MR primality test)
    const ln: u32 = 2 * Self::SECPARAM; // NOTE: length of n (i.e. special RSA modulus), ln will be used to generate all randomness and bases for public keys
    const lm: u32 = 256; // NOTE: length of each secret attribute in the credential, i.e. x = (m0, m1, ... m(M-1))
    const lin: u32 = 256; // NOTE: additional security parameter; both lm and lin set to 256 bits to improve security (i.e. SHA256 will be used here, instead of SHA1)
    const le: u32 = Self::lm + 2; // NOTE: length of e (i.e. exponent used in the signature, v ** e)
    const ls: u32 = Self::ln + Self::lm + Self::lin; // NOTE: length of s (i.e. random number used in the signature, b ** s)

    //RANGEPROOF
    const RANGEPROOF_ALG: RangeProof = RangeProof::Boudot2000;
    /* Security parameter - Half of the length of the Hash function output
    NOTE: i.e., 2*t bits is the length of the Hash function output.
    The soundness characteristic of the range proof is given by 2**(t−1).
    t = 80: Original value in [Boudot2000], appropriate for SHA-1 - sha160 (i.e. 2*t = 160 bits),
    replaced by t = 128, appropriate for SHA256 (i.e. 2*t = 256). */
    const t: u32 = 128;
    // Security parameter - Zero knowledge property is guaranteed given that 1∕l is negligible
    const l: u32 = 40;
    // Security parameter for the commitment - 2**s  must be negligible
    const s: u32 = 40;
    // Security parameter for the commitment - 2**s1 must be negligible
    const s1: u32 = 40;
    // Security parameter for the commitment - 2**s2 must be negligible
    const s2: u32 = 552;
}

impl Ciphersuite for CL2048Sha256 {
    type HashAlg = Sha256;
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL3072Sha256 {}

impl CLCiphersuite for CL3072Sha256 {
    const SECPARAM: u32 = 1536;
    const QSEC: u32 = 27; // NOTE: Miller-Rabin repetitions for primality testing of q prime. (Check NIST-FIPS 186-4, Table C.1, Column 2 (Integer.is_probably_prime runs a lukas test internally and "reps - 24" repetitions of the MR primality test)
    const ln: u32 = 2 * Self::SECPARAM; // NOTE: length of n (i.e. special RSA modulus), ln will be used to generate all randomness and bases for public keys
    const lm: u32 = 256; // NOTE: length of each secret attribute in the credential, i.e. x = (m0, m1, ... m(M-1))
    const lin: u32 = 256; // NOTE: additional security parameter; both lm and lin set to 256 bits to improve security (i.e. SHA256 will be used here, instead of SHA1)
    const le: u32 = Self::lm + 2; // NOTE: length of e (i.e. exponent used in the signature, v ** e)
    const ls: u32 = Self::ln + Self::lm + Self::lin; // NOTE: length of s (i.e. random number used in the signature, b ** s)

    //RANGEPROOF
    const RANGEPROOF_ALG: RangeProof = RangeProof::Boudot2000;
    /* Security parameter - Half of the length of the Hash function output
    NOTE: i.e., 2*t bits is the length of the Hash function output.
    The soundness characteristic of the range proof is given by 2**(t−1).
    t = 80: Original value in [Boudot2000], appropriate for SHA-1 - sha160 (i.e. 2*t = 160 bits),
    replaced by t = 128, appropriate for SHA256 (i.e. 2*t = 256). */
    const t: u32 = 128;
    // Security parameter - Zero knowledge property is guaranteed given that 1∕l is negligible
    const l: u32 = 40;
    // Security parameter for the commitment - 2**s  must be negligible
    const s: u32 = 40;
    // Security parameter for the commitment - 2**s1 must be negligible
    const s1: u32 = 40;
    // Security parameter for the commitment - 2**s2 must be negligible
    const s2: u32 = 552;
}

impl Ciphersuite for CL3072Sha256 {
    type HashAlg = Sha256;
}