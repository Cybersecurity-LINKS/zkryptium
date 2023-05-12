use bls12_381_plus::{Scalar, G2Projective};
use elliptic_curve::group::Curve;
use serde_derive::{Serialize, Deserialize};

// use super::key::Private;
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusPublicKey(pub G2Projective);

impl BBSplusPublicKey{
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_affine().to_compressed()
    }

    pub fn encode(&self) -> String {
        let pk_bytes = self.to_bytes();
        hex::encode(pk_bytes)
    }
}


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusSecretKey(pub Scalar);

impl BBSplusSecretKey{
    //in BE order
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = self.0.to_bytes();
        bytes.reverse();
        bytes
    }

    pub fn encode(&self) -> String {
        let sk_bytes = self.to_bytes();
        hex::encode(sk_bytes)
    }
}



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusKeyPair{
    private: BBSplusSecretKey,
    public: BBSplusPublicKey
}

impl BBSplusKeyPair {
    pub fn new(private: BBSplusSecretKey, public: BBSplusPublicKey) -> Self {
        Self{private, public}
    }

    pub fn public(&self) -> &BBSplusPublicKey{
        &self.public
    }

    pub fn private(&self) -> &BBSplusSecretKey{
        &self.private
    }
}