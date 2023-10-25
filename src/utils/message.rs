// Copyright 2023 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use digest::Digest;
use elliptic_curve::hash2curve::ExpandMsg;
use ff::Field;
use rand::RngCore;
use serde::{Serialize, Deserialize};



#[cfg(feature = "cl03")]
use crate::cl03::ciphersuites::CLCiphersuite;
#[cfg(feature = "cl03")]
use rug::{Integer, integer::Order};



#[cfg(feature = "bbsplus")]
use bls12_381_plus::Scalar;
#[cfg(feature = "bbsplus")]
use crate::bbsplus::ciphersuites::BbsCiphersuite;
#[cfg(feature = "bbsplus")]
use crate::utils::util::bbsplus_utils::hash_to_scalar_old;




pub const BBS_MESSAGE_LENGTH: usize = usize::MAX;


pub trait Message {
    type Value;
    fn random(rng: impl RngCore) -> Self;
    fn to_bytes_be(&self) -> [u8; 32];
    fn to_bytes_le(&self) -> [u8; 32];
    fn get_value(&self) -> Self::Value;
}

#[cfg(feature = "bbsplus")]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusMessage{
    pub value: Scalar
}

#[cfg(feature = "bbsplus")]
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

#[cfg(feature = "cl03")]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03Message{
    pub value: Integer
}
#[cfg(feature = "cl03")]
impl CL03Message {

    pub fn new(msg: Integer) -> Self {
        Self{value: msg}
    }

    pub fn map_message_to_integer_as_hash<C: CLCiphersuite>(data: &[u8]) -> Self 
    where C::HashAlg: Digest
    {
        let binding = <C::HashAlg as Digest>::digest(data);
        let msg_digest = binding.as_slice();
        let msg_integer = Integer::from_digits(msg_digest, Order::MsfBe);
        Self{value: msg_integer}

    }

}

#[cfg(feature = "bbsplus")]
impl Message for BBSplusMessage {

    type Value = Scalar;

    fn random(rng: impl RngCore) -> Self {

        Self::new(Scalar::random(rng))
    }

    //in BE
    fn to_bytes_be(&self) -> [u8; 32] {
        let bytes = self.value.to_be_bytes();
        // bytes.reverse();
        bytes
    }

    fn to_bytes_le(&self) -> [u8; 32] {
        self.value.to_le_bytes()
    }
    
    fn get_value(&self) -> Scalar {
        self.value
    }
}

#[cfg(feature = "cl03")]
impl Message for CL03Message {
    type Value = Integer;

    fn random(_rng: impl RngCore) -> Self {
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

