use elliptic_curve::group::Curve;
use serde::{Serialize, de::DeserializeOwned};

use super::{cl03_key::{CL03PublicKey, CL03SecretKey}, bbsplus_key::{BBSplusPublicKey, BBSplusSecretKey}};



pub trait PublicKey: Serialize + DeserializeOwned + Send + Sync + 'static {
    type Output: ?Sized;
    // type Params;
    fn to_bytes(&self) -> Self::Output;
    fn encode(&self) -> String;
    // fn get_params(&self) -> Self::Params;
}
pub trait PrivateKey: Serialize + DeserializeOwned + Send + Sync + 'static {
    type Output: ?Sized;
    fn to_bytes(&self) -> Self::Output;
    fn encode(&self) -> String;
}

impl PublicKey for BBSplusPublicKey{
    type Output = [u8; 96];
    // type Params = G2Projective;
    fn to_bytes(&self) -> Self::Output {
        self.0.to_affine().to_compressed()
    }

    fn encode(&self) -> String {
        let pk_bytes = self.to_bytes();
        hex::encode(pk_bytes)
    }

    // fn get_params(&self) -> Self::Params {
    //     self.0
    // }
}
impl PublicKey for CL03PublicKey{
    type Output = [u8; 512];
    // type Params = (Integer, Integer, Integer, Vec<(Integer, bool)>);
    fn encode(&self) -> String {
        todo!()
    }

    fn to_bytes(&self) -> Self::Output {
        todo!()
    }

    // fn get_params(&self) -> (Integer, Integer, Integer, Vec<(Integer, bool)>) {
    //     (self.N.clone(), self.b.clone(), self.c.clone(), self.a_bases.clone())
    // }
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

