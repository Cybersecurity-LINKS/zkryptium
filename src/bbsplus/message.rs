use std::process::Output;

use rand::RngCore;
use rug::Integer;
use bls12_381_plus::Scalar;



pub trait Message<const BYTES: usize> {
    fn new<B: AsRef<[u8]>>(data: B) -> Self;
    fn random(rng: impl RngCore) -> Self;
    fn to_bytes(&self) -> [u8; BYTES];
}

pub struct BBSplusMessage{
    value: Scalar
}

pub struct CL03Message{
    value: Integer
}

impl Message<64> for BBSplusMessage {

    fn new<B: AsRef<[u8]>>(data: B) -> Self {
        todo!()
    }

    fn random(rng: impl RngCore) -> Self {
        todo!()
    }

    fn to_bytes(&self) -> [u8; 64] {
        todo!()
    }
}

