use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::schemes::algorithms::Ciphersuite;

pub trait CLCiphersuite: Eq + 'static + Ciphersuite{
    const SECPARAM: u32;
    const ln: u32;   // NOTE: length of n (i.e. special RSA modulus), ln will be used to generate all randomness and bases for public keys
    const lm: u32;            // NOTE: length of each secret attribute in the credential, i.e. x = (m0, m1, ... m(M-1))
    const lin: u32;          // NOTE: additional security parameter; both lm and lin set to 256 bits to improve security (i.e. SHA256 will be used here, instead of SHA1)        
    const le: u32;         // NOTE: length of e (i.e. exponent used in the signature, v ** e)
    const ls: u32;  // NOTE: length of s (i.e. random number used in the signature, b ** s)                 
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
}

impl Ciphersuite for CLSha256 {
    type HashAlg = Sha256;      
}        


