// SPDX-FileCopyrightText: 2023 Fondazione LINKS
//
// SPDX-License-Identifier: APACHE-2.0

use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::schemes::algorithms::Ciphersuite;
use super::range_proof::RangeProof;

pub trait CLCiphersuite: Eq + 'static + Ciphersuite{
    const SECPARAM: u32;
    const ln: u32;   // NOTE: length of n (i.e. special RSA modulus), ln will be used to generate all randomness and bases for public keys
    const lm: u32;            // NOTE: length of each secret attribute in the credential, i.e. x = (m0, m1, ... m(M-1))
    const lin: u32;          // NOTE: additional security parameter; both lm and lin set to 256 bits to improve security (i.e. SHA256 will be used here, instead of SHA1)        
    const le: u32;         // NOTE: length of e (i.e. exponent used in the signature, v ** e)
    const ls: u32;  // NOTE: length of s (i.e. random number used in the signature, b ** s)

    // RANGE PROOFS
    const RANGEPROOF_ALG: RangeProof;
    const t: u32;
    const l: u32;
    const s: u32;
    const s1: u32;
    const s2: u32;         
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CLSha256{}

impl CLCiphersuite for CLSha256{
    const SECPARAM: u32 = 512;
    const ln: u32 = 2 * Self::SECPARAM;   // NOTE: length of n (i.e. special RSA modulus), ln will be used to generate all randomness and bases for public keys
    const lm: u32 = 256;            // NOTE: length of each secret attribute in the credential, i.e. x = (m0, m1, ... m(M-1))
    const lin: u32 = 256;          // NOTE: additional security parameter; both lm and lin set to 256 bits to improve security (i.e. SHA256 will be used here, instead of SHA1)        
    const le: u32 = Self::lm + 2;         // NOTE: length of e (i.e. exponent used in the signature, v ** e)
    const ls: u32 = Self::ln + Self::lm + Self::lin;  // NOTE: length of s (i.e. random number used in the signature, b ** s)            

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

impl Ciphersuite for CLSha256 {
    type HashAlg = Sha256;      
}




