// use std::marker::PhantomData;
// use core::fmt::Debug;
// use core::fmt::Display;
// use core::fmt::Formatter;
// use core::fmt::Result;
// use zeroize::Zeroize;

use std::{marker::PhantomData, process::Output};

use bls12_381_plus::{Scalar, G2Projective};
use elliptic_curve::group::Curve;
use rug::Integer;
use serde::{Serialize, Deserialize, de::DeserializeOwned};

use crate::schemes::algorithms::{Scheme, CL03, BBSplus};

use super::{cl03_key::{CL03PublicKey, CL03SecretKey}, bbsplus_key::{BBSplusPublicKey, BBSplusSecretKey}};



pub trait PublicKey: Serialize + DeserializeOwned + Send + Sync + 'static {
    type Output;
    fn to_bytes(&self) -> Self::Output;
    fn encode(&self) -> String;
}
pub trait PrivateKey: Serialize + DeserializeOwned + Send + Sync + 'static {
    type Output;
    fn to_bytes(&self) -> Self::Output;
    fn encode(&self) -> String;
}

impl PublicKey for BBSplusPublicKey{
    type Output = [u8;96];
    fn to_bytes(&self) -> Self::Output {
        self.0.to_affine().to_compressed()
    }

    fn encode(&self) -> String {
        let pk_bytes = self.to_bytes();
        hex::encode(pk_bytes)
    }
}
impl PublicKey for CL03PublicKey{
    type Output = [u8; 512];

    fn encode(&self) -> String {
        todo!()
    }

    fn to_bytes(&self) -> Self::Output {
        todo!()
    }
}

impl PrivateKey for BBSplusSecretKey{
    type Output = [u8; 32];
    //in BE order
    fn to_bytes(&self) -> Self::Output{
        let mut bytes = self.0.to_bytes();
        bytes.reverse();
        bytes
    }

    fn encode(&self) -> String {
        let sk_bytes = self.to_bytes();
        hex::encode(sk_bytes)
    }
}
impl PrivateKey for CL03SecretKey{
    type Output = [u8; 512];
    fn encode(&self) -> String {
        todo!()
    }

    fn to_bytes(&self) -> Self::Output {
        todo!()
    }
}
