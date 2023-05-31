use std::process::Output;

use digest::{HashMarker, Digest};
use elliptic_curve::hash2curve::ExpandMsg;
use ff::Field;
use rand::RngCore;
use rug::{Integer, integer::Order};
use bls12_381_plus::Scalar;
use serde::{Serialize, Deserialize};

use crate::{schemes::algorithms::Scheme, utils::util::{hash_to_scalar, hash_to_scalar_old}, cl03::ciphersuites::CLCiphersuite};

use super::ciphersuites::BbsCiphersuite;

pub const BBS_MESSAGE_LENGTH: usize = usize::MAX;


pub trait Message {
    type Value;
    fn random(rng: impl RngCore) -> Self;
    fn to_bytes_be(&self) -> [u8; 32];
    fn to_bytes_le(&self) -> [u8; 32];
    fn get_value(&self) -> Self::Value;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusMessage{
    pub value: Scalar
}

impl BBSplusMessage {

    pub fn new(msg: Scalar) -> Self{
        Self{value: msg}
    }

    pub fn map_message_to_scalar_as_hash<C: BbsCiphersuite>(data: &[u8], dst: Option<&[u8]>) -> Self 
    where
        C::Expander: for<'a> ExpandMsg<'a>,
    {
        let binding = [C::ID, "MAP_MSG_TO_SCALAR_AS_HASH_".as_bytes()].concat();
        let default_dst = binding.as_slice();
        let dst = dst.unwrap_or(default_dst);

        if data.len() > BBS_MESSAGE_LENGTH-1 && dst.len() > 255 {
            panic!("INVALID");
        }

        // let scalar = hash_to_scalar::<C>(data, Some(dst));
        let scalar = hash_to_scalar_old::<C>(data, 1, Some(dst))[0];
        Self { value: scalar }

    }

}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03Message{
    pub value: Integer
}

impl CL03Message {

    pub fn new(msg: Integer) -> Self {
        Self{value: msg}
    }

    pub fn map_message_to_integer_as_hash<C: CLCiphersuite>(data: &[u8]) -> Self 
    where C::HashAlg: Digest
    {
        let binding = <C::HashAlg as Digest>::digest(data);
        let msg_digest = binding.as_slice();
        let msg_integer = Integer::from_digits(msg_digest, Order::Lsf);
        Self{value: msg_integer}

    }
}

impl Message for BBSplusMessage {

    type Value = Scalar;

    fn random(rng: impl RngCore) -> Self {

        Self::new(Scalar::random(rng))
    }

    //in BE
    fn to_bytes_be(&self) -> [u8; 32] {
        let mut bytes = self.value.to_bytes();
        bytes.reverse();
        bytes
    }

    fn to_bytes_le(&self) -> [u8; 32] {
        self.value.to_bytes()
    }
    
    fn get_value(&self) -> Scalar {
        self.value
    }
}

impl Message for CL03Message {
    type Value = Integer;

    fn random(rng: impl RngCore) -> Self {
        todo!()
    }

    fn to_bytes_be(&self) -> [u8; 32] {
        todo!()
    }

    fn to_bytes_le(&self) -> [u8; 32] {
        todo!()
    }

    fn get_value(&self) -> Integer {
        self.value.clone()
    }
}

