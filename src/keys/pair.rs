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

use crate::schemes::algorithms::Scheme;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyPair<S: Scheme> {
    pub(crate) public: S::PubKey,
    pub(crate) private: S::PrivKey,
}

impl<S> KeyPair<S>
where
    S: Scheme,
{
    pub fn public_key(&self) -> &S::PubKey {
        &self.public
    }

    pub fn private_key(&self) -> &S::PrivKey {
        &self.private
    }

    /// Returns the couple `(sk, pk)`.
    pub fn into_parts(self) -> (S::PrivKey, S::PubKey) {
        (self.private, self.public)
    }

    #[cfg(feature = "std")]
    pub fn write_keypair_to_file(&self, file: Option<String>) {
        println!("writhing to file...");

        let file = file.unwrap_or_else(|| String::from("../fixtures/fixture_data/keyPair.json"));
        let current_path = std::env::current_dir().unwrap();
        let file_to_write = current_path.join(file);

        if  std::fs::write(
            &file_to_write,
            serde_json::to_string_pretty(&self).expect("failed to serializing key pair"),
        ).is_err() {
            panic!("failed to write key pair to file: {file_to_write:?}");
        }
    }
}
