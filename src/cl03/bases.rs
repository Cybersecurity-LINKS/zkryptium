// Copyright 2025 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::keys::CL03PublicKey;
use crate::utils::random::random_qr;
use rug::Integer;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bases(pub Vec<Integer>);

impl Bases {
    pub fn generate(pk: &CL03PublicKey, n_attributes: usize) -> Self {
        let mut a_bases: Vec<Integer> = Vec::new();
        for _i in 0..n_attributes {
            let a = random_qr(&pk.N);
            a_bases.push(a);
        }

        Self(a_bases)
    }
}
