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


use elliptic_curve::hash2curve::ExpandMsg;
use serde::{Serialize, Deserialize};
use crate::errors::Error;


#[cfg(feature = "cl03")]
use crate::cl03::ciphersuites::CLCiphersuite;
#[cfg(feature = "cl03")]
use digest::Digest;
#[cfg(feature = "cl03")]
use rug::{Integer, integer::Order};



#[cfg(feature = "bbsplus")]
use bls12_381_plus::Scalar;
#[cfg(feature = "bbsplus")]
use crate::bbsplus::ciphersuites::BbsCiphersuite;
#[cfg(feature = "bbsplus")]
use super::util::bbsplus_utils::hash_to_scalar;


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


    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-messages-to-scalars
    /// 
    /// # Description
    /// The messages_to_scalars operation is used to map a list of messages to their respective scalar values
    /// 
    /// # Inputs:
    /// * `messages` (REQUIRED), a vector of octet strings.
    /// * `api_id` (REQUIRED), octet string. It could be an empty octet string
    /// 
    /// # Output:
    /// * a vector of [`BBSplusMessage`], which is a wrapper to a `Scalar` or [`Error`].
    /// 
    pub fn messages_to_scalar<CS: BbsCiphersuite>(messages: &[Vec<u8>], api_id: &[u8]) -> Result<Vec<Self>, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>
    {

        let map_dst = [api_id, CS::MAP_MSG_SCALAR].concat();
        let mut msg_scalars: Vec<Self> = Vec::new();
        for m in messages {
            let scalar = hash_to_scalar::<CS>(m, &map_dst)?;
            msg_scalars.push(Self { value: scalar })
        }

        Ok(msg_scalars)
    }


 
    /// # Description
    /// The `map_message_to_scalar_as_hash` operation is used to map a single message to its respective scalar value
    /// 
    /// # Inputs:
    /// * `data` (REQUIRED), an octet string representing a single message.
    /// * `api_id` (REQUIRED), octet string. It could be an empty octet string
    /// 
    /// # Output:
    /// * a [`BBSplusMessage`], which is a wrapper to a `Scalar` or [`Error`].
    ///
    pub fn map_message_to_scalar_as_hash<CS: BbsCiphersuite>(data: &[u8], api_id: &[u8]) -> Result<Self, Error> 
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {

        let map_dst = [api_id, CS::MAP_MSG_SCALAR].concat();
        let scalar = hash_to_scalar::<CS>(data, &map_dst)?;
        
        Ok(Self { value: scalar })

    }

    pub fn to_bytes_be(&self) -> [u8; Scalar::BYTES] {
        self.value.to_be_bytes()
    }

    pub fn from_bytes_be(bytes: &[u8; Scalar::BYTES]) -> Result<Self, Error> {
        let s = Scalar::from_be_bytes(bytes);
        if s.is_none().into() {
            return Err(Error::Unspecified)
        }
        Ok(BBSplusMessage{value: s.unwrap()})
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

    pub fn get_value(&self) -> Integer {
        self.value.clone()
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

