use std::process::Output;

use digest::{HashMarker, Digest};
use elliptic_curve::hash2curve::ExpandMsg;
use rand::RngCore;
use rug::{Integer, integer::Order};
use bls12_381_plus::Scalar;

use crate::{schemes::algorithms::Scheme, utils::util::hash_to_scalar, cl03::ciphersuites::CLCiphersuite};

use super::ciphersuites::BbsCiphersuite;

pub const BBS_MESSAGE_LENGTH: usize = usize::MAX;


pub trait Message {
    fn random(rng: impl RngCore) -> Self;
    fn to_bytes(&self) -> [u8; 32];
}

pub struct BBSplusMessage{
    value: Scalar
}

impl BBSplusMessage {

    fn new(msg: Scalar) -> Self{
        Self{value: msg}
    }

    fn map_message_to_scalar_as_hash<C: BbsCiphersuite>(data: &[u8], dst: Option<&[u8]>) -> Self 
    where
        C::Expander: for<'a> ExpandMsg<'a>,
    {
        let binding = [C::ID, "MAP_MSG_TO_SCALAR_AS_HASH_".as_bytes()].concat();
        let default_dst = binding.as_slice();
        let dst = dst.unwrap_or(default_dst);

        if data.len() > BBS_MESSAGE_LENGTH-1 && dst.len() > 255 {
            panic!("INVALID");
        }

        let scalar = hash_to_scalar::<C>(data, Some(dst));

        Self { value: scalar }

    }
}

pub struct CL03Message{
    value: Integer
}

impl CL03Message {

    fn new(msg: Integer) -> Self {
        Self{value: msg}
    }

    fn map_message_to_integer_as_hash<C: CLCiphersuite>(data: &[u8]) -> Self 
    where C::HashAlg: Digest
    {
        let binding = <C::HashAlg as Digest>::digest(data);
        let msg_digest = binding.as_slice();
        let msg_integer = Integer::from_digits(msg_digest, Order::Lsf);
        Self{value: msg_integer}

    }
}

impl Message for BBSplusMessage {


    fn random(rng: impl RngCore) -> Self {
        todo!()
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.value.to_bytes()
    }
}

