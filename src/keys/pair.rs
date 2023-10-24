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


use std::env;
use bls12_381_plus::G2Affine;
use bls12_381_plus::G2Projective;
use bls12_381_plus::Scalar;
use ff::Field;
use hkdf::Hkdf;
use rand::Rng;
use rand::RngCore;
use rug::Integer;
use rug::integer::IsPrime;
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;

use crate::bbsplus::ciphersuites::BbsCiphersuite;
use crate::cl03::ciphersuites::CLCiphersuite;

use crate::schemes::algorithms::BBSplus;
use crate::schemes::algorithms::CL03;
use crate::schemes::algorithms::Scheme;
use crate::utils::random::random_prime;
use crate::utils::random::random_qr;
use crate::bbsplus::keys::BBSplusPublicKey;
use crate::bbsplus::keys::BBSplusSecretKey;
use crate::cl03::keys::CL03PublicKey;
use crate::cl03::keys::CL03SecretKey;
use sha2::Digest;


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyPair<S: Scheme>{
    pub(crate) public: S::PubKey,
    pub(crate) private: S::PrivKey,
}

impl <S> KeyPair<S> 
where S: Scheme
{

    pub fn public_key(&self) -> &S::PubKey{
        &self.public
    }

    pub fn private_key(&self) -> &S::PrivKey {
        &self.private
    }

    pub fn write_keypair_to_file(&self, file: Option<String>)
    {
        println!("writhing to file...");

        // #[derive(Deserialize, Serialize, Debug)]
        // #[allow(non_snake_case)]
        // struct FileToWrite {
        //     keyPair: Self
        // }

        // let key_pair_to_write: FileToWrite = FileToWrite { 
        //     keyPair: key_pair
        // };

        let file = file.unwrap_or(String::from("../fixtures/fixture_data/keyPair.json"));
        let current_path = env::current_dir().unwrap();
        let file_to_write = current_path.join(file);

        std::fs::write(
            &file_to_write, 
            serde_json::to_string_pretty(
                &self
            ).expect("failed to serializing key pair")
        ).expect(&format!("failed to write key pair to file: {}", file_to_write.to_str().unwrap()));
    }
}






