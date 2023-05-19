use digest::HashMarker;
use serde::{Serialize, Deserialize, de::DeserializeOwned};
use sha2::Sha256;
use sha3::Shake256;
use std::marker::PhantomData;
use crate::{keys::{key::{PrivateKey, PublicKey}, bbsplus_key::{BBSplusSecretKey, BBSplusPublicKey}, cl03_key::{CL03SecretKey, CL03PublicKey}}, bbsplus::ciphersuites::{BbsCiphersuite, Bls12381Shake256, Bls12381Sha256}, cl03::ciphersuites::{CLCiphersuite, CLSha256}};

pub type BBSplusShake256 = BBSplus<Bls12381Shake256>;
pub type BBSplusSha256 = BBSplus<Bls12381Sha256>;
pub type CL03Sha256 = CL03<CLSha256>;



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplus<CS: BbsCiphersuite>(PhantomData<CS>);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03<CS: CLCiphersuite>(PhantomData<CS>);


pub trait Ciphersuite: 'static + Eq{
    type HashAlg: HashMarker;

}

impl Ciphersuite for Bls12381Sha256{
    type HashAlg = Shake256;

}
impl Ciphersuite for Bls12381Shake256{
    type HashAlg = Sha256;

}


pub trait Scheme:
Eq
+ 'static
+ Sized 
+ Serialize 
+ DeserializeOwned {
    type Ciphersuite: Ciphersuite;
    type PrivKey: PrivateKey;
    type PubKey: PublicKey;
}

impl <CS: BbsCiphersuite> Scheme for BBSplus<CS> {
    type Ciphersuite = CS;
    type PrivKey = BBSplusSecretKey;
    type PubKey = BBSplusPublicKey;
}

impl <CS: CLCiphersuite> Scheme for CL03<CS> {
    type Ciphersuite = CS;
    type PrivKey = CL03SecretKey;
    type PubKey = CL03PublicKey;


}