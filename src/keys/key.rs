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
        self.to_bytes()
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
        self.to_bytes()
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

