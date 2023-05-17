use core::result::Result;
use std::marker::PhantomData;

use crate::schemes::algorithms::Scheme;

/// A common interface for digital signature creation.
pub trait Sign {
    /// The private key type of this signature implementation.
    type Private: ?Sized;
  
    /// The output type of this signature implementation.
    type Output;
  
    /// Signs the given `message` with `key` and returns a digital signature.
    fn sign(message: &[u8], key: &Self::Private) -> Self::Output;
}


/// A common interface for digital signature verification
pub trait Verify {
    /// The public key type of this signature implementation.
    type Public: ?Sized;
  
    /// Verifies the authenticity of `data` and `signature` with `key`.
    fn verify(message: &[u8], signature: &[u8], key: &Self::Public) -> bool;
}



// pub struct Signature<S: Scheme>{

// }


