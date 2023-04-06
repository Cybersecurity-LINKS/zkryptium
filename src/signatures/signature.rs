use core::result::Result;

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




// impl<T> Sign for Ed25519<T>
// where
//   T: AsRef<[u8]> + ?Sized,
// {
//   type Private = T;
//   type Output = [u8; Ed25519::SIGNATURE_LENGTH];
//   /// Computes an EdDSA signature using an Ed25519 private key.
//   ///
//   /// The private key must be a 32-byte seed in compliance with [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032#section-3.2).
//   /// Other implementations often use another format. See [this blog post](https://blog.mozilla.org/warner/2011/11/29/ed25519-keys/) for further explanation.
//   fn sign(message: &[u8], key: &Self::Private) -> Result<Self::Output> {
//     ed25519_private_try_from_bytes(key.as_ref()).map(|key| key.sign(message).to_bytes())
//   }
// }

// impl<T> Verify for Ed25519<T>
// where
//   T: AsRef<[u8]> + ?Sized,
// {
//   type Public = T;

//   /// Verifies an EdDSA signature against an Ed25519 public key.
//   fn verify(message: &[u8], signature: &[u8], key: &Self::Public) -> Result<()> {
//     let key: ed25519::PublicKey = ed25519_public_try_from_bytes(key.as_ref())?;
//     let sig: ed25519::Signature = parse_signature(signature)?;

//     if key.verify(&sig, message) {
//       Ok(())
//     } else {
//       Err(Error::InvalidProofValue("ed25519"))
//     }
//   }
// }