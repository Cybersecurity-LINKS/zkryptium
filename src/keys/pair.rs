use crate::keys::type_::KeyType;
use crate::keys::key::PublicKey;
use crate::keys::key::PrivateKey;

// #[derive(Clone, Debug)]
// pub struct KeyPair {
//   type_: KeyType,
//   public: PublicKey,
//   private: PrivateKey,
// }


pub trait KeyPair {
    type PublicKey;
    type PrivateKey;

    fn new() -> Self;
}

// impl KeyPair {
//     /// Creates a new [`KeyPair`] with the given [`key type`][`KeyType`].
//     pub fn new(type_: KeyType) -> Result<Self> {
//       let (public, private): (PublicKey, PrivateKey) = match type_ {
//         KeyType::Ed25519 => {
//           let secret: ed25519::SecretKey = ed25519::SecretKey::generate()?;
//           let public: ed25519::PublicKey = secret.public_key();
  
//           let private: PrivateKey = secret.to_bytes().to_vec().into();
//           let public: PublicKey = public.to_bytes().to_vec().into();
  
//           (public, private)
//         }
//         KeyType::X25519 => {
//           let secret: x25519::SecretKey = x25519::SecretKey::generate()?;
//           let public: x25519::PublicKey = secret.public_key();
  
//           let private: PrivateKey = secret.to_bytes().to_vec().into();
//           let public: PublicKey = public.to_bytes().to_vec().into();
//           (public, private)
//         }
//       };
  
//       Ok(Self { type_, public, private })
//     }
// }