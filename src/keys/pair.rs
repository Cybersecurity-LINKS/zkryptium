use std::marker::PhantomData;

use rug::Integer;
use rug::integer::IsPrime;

use crate::keys::type_::KeyType;
// use crate::keys::key::PublicKey;
// use crate::keys::key::PrivateKey;
use crate::keys::cl03_key::CL03KeyPair;
use crate::utils::random::random_prime;
use crate::utils::random::random_qr;

use super::bbsplus_key::BBSplusKeyPair;
use super::bbsplus_key::BBSplusPublicKey;
use super::bbsplus_key::BBSplusSecretKey;
use super::cl03_key::CL03PublicKey;
use super::cl03_key::CL03SecretKey;
// use super::key::Private;
// use super::key::Public;

// #[derive(Clone, Debug)]
// pub struct KeyPair {
//   type_: KeyType,
//   public: PublicKey,
//   private: PrivateKey,
// }


// pub trait KeyPair {
//     type PublicKey;
//     type PrivateKey;

//     fn new() -> Self;
// }

pub trait IKeyPair{}

impl IKeyPair for CL03KeyPair {}

impl IKeyPair for BBSplusKeyPair {}

#[derive(Clone, Debug)]
pub struct KeyPair<P: IKeyPair> {
    phantom: PhantomData<P>,
}

impl KeyPair<CL03KeyPair> {
    pub fn generate() -> CL03KeyPair {
        let n = 512; //SECPARAM
        let mut pprime = random_prime(n);
        let mut p = Integer::from(2) * pprime.clone() + Integer::from(1);
        loop{
            // println!("{} INT", p);
            // let digits = p.to_digits::<u8>(Order::MsfBe);
            // let bignum = BigUint::from_bytes_be(&digits);
            // println!("{} BIGNUM", bignum);
            if p.is_probably_prime(50) !=IsPrime::No {
                break;
            }
            pprime = random_prime(n);
            p = Integer::from(2) * pprime + Integer::from(1);
        }

        let mut qprime = random_prime(n);
        let mut q = Integer::from(2) * qprime.clone() + Integer::from(1);
        loop{
            // println!("{} INT", p);
            // let digits = p.to_digits::<u8>(Order::MsfBe);
            // let bignum = BigUint::from_bytes_be(&digits);
            // println!("{} BIGNUM", bignum);
            if p != q && q.is_probably_prime(100) !=IsPrime::No {
                break;
            }
            qprime = random_prime(n);
            q = Integer::from(2) * qprime + Integer::from(1);
        }

        let N = p.clone() * q.clone();
    
        let mut a_bases: Vec<Integer> = Vec::new();
        let a0 = random_qr(&N);

        a_bases.push(a0);

        let b = random_qr(&N);
        let c = random_qr(&N);

        let pk = CL03PublicKey::new(N, b, c, a_bases);
        let sk = CL03SecretKey::new(p, q);

        let pair = CL03KeyPair::new(sk, pk);

        pair

    }
}

impl KeyPair<BBSplusKeyPair>{
    pub fn generate(test_param: bool) -> BBSplusKeyPair{
        let private = BBSplusSecretKey{};
        let public = BBSplusPublicKey{};
        BBSplusKeyPair::new(private, public)
    }
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