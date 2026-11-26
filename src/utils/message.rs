// Copyright 2026 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(feature = "bbsplus")]
/// Module for handling BBS+ messages and related operations.
pub mod bbsplus_message {

    use crate::bbsplus::ciphersuites::BbsCiphersuite;
    use crate::errors::Error;
    use crate::utils::util::bbsplus_utils::hash_to_scalar;
    use bls12_381_plus::Scalar;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    /// A struct representing a BBS+ message with a scalar value.
    pub struct BBSplusMessage {
        /// The scalar value of the BBS+ message.
        pub value: Scalar,
    }

    impl BBSplusMessage {
        /// Creates a new `BBSplusMessage` with the given scalar value.
        pub fn new(msg: Scalar) -> Self {
            Self { value: msg }
        }

        /// <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-15#name-messages-to-scalars>
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
        pub fn messages_to_scalar<CS: BbsCiphersuite>(
            messages: &[Vec<u8>],
            api_id: &[u8],
        ) -> Result<Vec<Self>, Error> {
            let map_dst = [api_id, CS::MAP_MSG_SCALAR].concat();
            let mut msg_scalars: Vec<Self> = Vec::new();
            for m in messages {
                let scalar = hash_to_scalar::<CS>(m, &map_dst)?;
                msg_scalars.push(Self { value: scalar })
            }

            Ok(msg_scalars)
        }

        /// # Description
        /// The `map_message_to_scalar_as_hash` operation is used to map a single message
        /// to its respective scalar value
        ///
        /// # Inputs:
        /// * `data` (REQUIRED), an octet string representing a single message.
        /// * `api_id` (REQUIRED), octet string. It could be an empty octet string
        ///
        /// # Output:
        /// * a [`BBSplusMessage`], which is a wrapper to a `Scalar` or [`Error`].
        ///
        pub fn map_message_to_scalar_as_hash<CS: BbsCiphersuite>(
            data: &[u8],
            api_id: &[u8],
        ) -> Result<Self, Error> {
            let map_dst = [api_id, CS::MAP_MSG_SCALAR].concat();
            let scalar = hash_to_scalar::<CS>(data, &map_dst)?;

            Ok(Self { value: scalar })
        }

        /// Converts the BBSplusMessage to a big-endian byte array.
        pub fn to_bytes_be(&self) -> [u8; Scalar::BYTES] {
            self.value.to_be_bytes()
        }

        /// Converts a big-endian byte array to a BBSplusMessage.
        ///         
        /// # Output:
        /// * a [`BBSplusMessage`], which is a wrapper to a `Scalar` or [`Error`].
        ///
        pub fn from_bytes_be(bytes: &[u8; Scalar::BYTES]) -> Result<Self, Error> {
            let s = Scalar::from_be_bytes(bytes);
            if s.is_none().into() {
                return Err(Error::Unspecified);
            }
            Ok(BBSplusMessage { value: s.unwrap() })
        }
    }

    #[cfg(test)]
    mod tests;
}

#[cfg(feature = "cl03")]
/// Module for handling CL03 messages and related operations.
pub mod cl03_message {

    use crate::cl03::ciphersuites::CLCiphersuite;
    use digest::Digest;
    use rug::{integer::Order, Integer};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
    /// A struct representing a CL03 message with an integer value.
    pub struct CL03Message {
        /// The integer value of the CL03 message.
        pub value: Integer,
    }

    impl CL03Message {
        /// Creates a new `CL03Message` with the given integer value.
        pub fn new(msg: Integer) -> Self {
            Self { value: msg }
        }

        ///Gets the integer value of the CL03 message.
        pub fn get_value(&self) -> Integer {
            self.value.clone()
        }

        /// `true` if the value is in the CL03 message space `[0, 2^lm)`.
        ///
        /// Signing and verification reject messages outside it: from a signature `(e, s, v)` on
        /// `m`, `(e, s, v * a^k)` is a valid signature on `m + k * e`, and only the range check
        /// (with `e > 2^(lm+1)`) makes those values invalid messages.
        pub fn is_in_range<C: CLCiphersuite>(&self) -> bool {
            self.value >= 0 && self.value.significant_bits() <= C::lm
        }

        /// Create a new `CL03Message` from the hash of byte array.
        pub fn map_message_to_integer_as_hash<C: CLCiphersuite>(data: &[u8]) -> Self
        where
            C::HashAlg: Digest,
        {
            let binding = <C::HashAlg as Digest>::digest(data);
            let msg_digest = binding.as_slice();
            let msg_integer = Integer::from_digits(msg_digest, Order::MsfBe);
            Self { value: msg_integer }
        }
    }
}
