use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::bbsplus::ciphersuites::Ciphersuite;

pub trait CLCiphersuite: Eq + 'static + Ciphersuite{
    const SECPARAM: usize;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CLSha256{}

impl CLCiphersuite for CLSha256{
    const SECPARAM: usize = 512;
}

impl Ciphersuite for CLSha256 {
    type HashAlg = Sha256;
}

