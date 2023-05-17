use serde::{Serialize, Deserialize, de::DeserializeOwned};

use crate::keys::{key::{PrivateKey, PublicKey}, bbsplus_key::{BBSplusSecretKey, BBSplusPublicKey}, cl03_key::{CL03SecretKey, CL03PublicKey}};

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplus;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03;


pub trait Scheme:
Eq
+ 'static
+ Sized 
+ Serialize 
+ DeserializeOwned {

    type PrivKey: PrivateKey;
    type PubKey: PublicKey;
}

impl Scheme for BBSplus {

    type PrivKey = BBSplusSecretKey;
    type PubKey = BBSplusPublicKey;
}

impl Scheme for CL03 {

    type PrivKey = CL03SecretKey;
    type PubKey = CL03PublicKey;
}