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

#[cfg(feature = "min_bbs")]
pub mod bbsplus_message {
    use alloc::vec::Vec;
    use crate::bbsplus::ciphersuites::BbsCiphersuite;
    use crate::errors::Error;
    use crate::utils::util::bbsplus_utils::hash_to_scalar;
    use bls12_381_plus::Scalar;
    use elliptic_curve::hash2curve::ExpandMsg;
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct BBSplusMessage {
        pub value: Scalar,
    }

    impl BBSplusMessage {
        pub fn new(msg: Scalar) -> Self {
            Self { value: msg }
        }

        /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-messages-to-scalars
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
        ) -> Result<Vec<Self>, Error>
        where
            CS::Expander: for<'a> ExpandMsg<'a>,
        {
            let map_dst = [api_id, CS::MAP_MSG_SCALAR].concat();
            messages.into_iter().map(|m| Ok( Self{ value: hash_to_scalar::<CS>(m, &map_dst)?})).collect()
/*
            let mut msg_scalars: Vec<Self> = Vec::new();
            for m in messages {
                let scalar = hash_to_scalar::<CS>(m, &map_dst)?;
                msg_scalars.push(Self { value: scalar })
            }

            Ok(msg_scalars)
            */
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
        pub fn map_message_to_scalar_as_hash<CS: BbsCiphersuite>(
            data: &[u8],
            api_id: &[u8],
        ) -> Result<Self, Error>
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
                return Err(Error::Unspecified);
            }
            Ok(BBSplusMessage { value: s.unwrap() })
        }
    }

    #[cfg(test)]
    mod tests {

        use crate::bbsplus::ciphersuites::BbsCiphersuite;
        use crate::schemes::algorithms::Scheme;
        use crate::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
        use crate::utils::message::bbsplus_message::BBSplusMessage;
        use elliptic_curve::hash2curve::ExpandMsg;
        use std::fs;

        //MAP MESSAGE TO SCALAR - SHA256

        #[test]
        fn map_message_to_scalar_as_hash_sha256() {
            map_message_to_scalar_as_hash::<BbsBls12381Sha256>(
                "./fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json",
            );
        }

        //MESSAGES TO SCALAR - SHAKE256

        #[test]
        fn map_message_to_scalar_as_hash_shake256() {
            map_message_to_scalar_as_hash::<BbsBls12381Shake256>(
                "./fixture_data/bls12-381-shake-256/MapMessageToScalarAsHash.json",
            );
        }

        #[test]
        fn messages_to_scalars_sha256() {
            messages_to_scalars::<BbsBls12381Sha256>(
                "./fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json",
            );
        }

        //MESSAGES TO SCALAR - SHAKE256

        #[test]
        fn messages_to_scalars_shake256() {
            messages_to_scalars::<BbsBls12381Shake256>(
                "./fixture_data/bls12-381-shake-256/MapMessageToScalarAsHash.json",
            );
        }

        fn map_message_to_scalar_as_hash<S: Scheme>(filename: &str)
        where
            S::Ciphersuite: BbsCiphersuite,
            <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
        {
            let data = fs::read_to_string(filename).expect("Unable to read file");
            let json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
            eprintln!("{}", json["caseName"]);
            let cases = json["cases"].as_array().unwrap();

            let mut boolean = true;
            for c in cases {
                let msg = &c["message"];

                let msg_hex = hex::decode(msg.as_str().unwrap()).unwrap();

                let out = hex::encode(
                    BBSplusMessage::map_message_to_scalar_as_hash::<S::Ciphersuite>(
                        &msg_hex,
                        <S::Ciphersuite as BbsCiphersuite>::API_ID,
                    )
                    .unwrap()
                    .to_bytes_be(),
                );
                let out_expected = c["scalar"].as_str().unwrap();

                if out != out_expected {
                    boolean = false;
                };
            }

            assert_eq!(boolean, true);
        }

        fn messages_to_scalars<S: Scheme>(filename: &str)
        where
            S::Ciphersuite: BbsCiphersuite,
            <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
        {
            let data = fs::read_to_string(filename).expect("Unable to read file");
            let json: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
            eprintln!("{}", json["caseName"]);
            let mut messages = Vec::new();
            let mut scalars = Vec::new();
            json["cases"].as_array().unwrap().iter().for_each(|v| {
                let msg = v["message"].as_str().unwrap();
                messages.push(hex::decode(msg).unwrap());
                let s = v["scalar"].as_str().unwrap();
                scalars.push(s.to_string());
            });

            let message_scalars = BBSplusMessage::messages_to_scalar::<S::Ciphersuite>(
                &messages,
                <S::Ciphersuite as BbsCiphersuite>::API_ID,
            )
            .unwrap();

            let message_scalars_hex: Vec<String> = message_scalars
                .iter()
                .map(|s| hex::encode(s.to_bytes_be()))
                .collect();

            assert_eq!(scalars, message_scalars_hex);
        }
    }
}

#[cfg(feature = "cl03")]
pub mod cl03_message {

    use crate::cl03::ciphersuites::CLCiphersuite;
    use digest::Digest;
    use rug::{integer::Order, Integer};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
    pub struct CL03Message {
        pub value: Integer,
    }

    impl CL03Message {
        pub fn new(msg: Integer) -> Self {
            Self { value: msg }
        }

        pub fn get_value(&self) -> Integer {
            self.value.clone()
        }

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
