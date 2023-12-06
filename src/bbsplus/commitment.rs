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

use bls12_381_plus::{Scalar, G1Projective};
use elliptic_curve::hash2curve::ExpandMsg;
use serde::{Deserialize, Serialize};
use crate::{utils::message::{Message, BBSplusMessage}, bbsplus::{ciphersuites::BbsCiphersuite, generators::Generators}, schemes::algorithms::BBSplus, utils::util::bbsplus_utils::{calculate_random_scalars, subgroup_check_g1}, schemes::generics::Commitment};
use super::keys::BBSplusPublicKey;



#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusCommitment {
    pub value: G1Projective,
    pub s_prime: Scalar
}



impl <CS: BbsCiphersuite> Commitment<BBSplus<CS>> {

    pub fn commit(messages: &[BBSplusMessage], generators: Option<&Generators>, pk: &BBSplusPublicKey, unrevealed_message_indexes: &[usize]) -> Self
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let L = messages.len();

        let s_prime = calculate_random_scalars::<CS>(1, None);

        if unrevealed_message_indexes.is_empty() {
            panic!("Unrevealed message indexes empty");
        }

        let generators = match generators {
            Some(gens) => gens.clone(),
            None => {
                let gens = Generators::create::<CS>(Some(pk), L+2);
                gens
            }
            
        };


        if unrevealed_message_indexes.iter().max().unwrap() >= &generators.message_generators.len() {
            panic!("Non enought generators!");
        }

        if subgroup_check_g1(generators.g1_base_point) == false {
            panic!("Failed subgroup check");
        }

        for i in unrevealed_message_indexes {
            if subgroup_check_g1(generators.message_generators[*i]) == false {
                panic!("Failed subgroup check");
            }
        }

        let mut commitment = generators.q1 * s_prime[0];

        // let mut index: usize = 0;

        for i in unrevealed_message_indexes {
            // commitment = commitment + (gens.message_generators[*i] * Scalar::from_bytes(&messages[index].to_bytes()).unwrap());
            commitment += generators.message_generators.get(*i).expect("index overflow") * &messages.get(*i).expect("Index overflow").get_value();
        
            // index = index + 1;
        }
        
        Self::BBSplus(BBSplusCommitment{value: commitment, s_prime: s_prime[0]})

    }

    pub fn value(&self) -> &G1Projective {
        match self {
            Self::BBSplus(inner) => &inner.value,
            _ => panic!("Cannot happen!")
        }
    }

    pub fn bbsPlusCommitment(&self) -> &BBSplusCommitment {
        match self {
            Self::BBSplus(inner) => &inner,
            _ => panic!("Cannot happen!"),
        }
    }

    pub fn s_prime(&self) -> &Scalar {
        match self {
            Self::BBSplus(inner) => &inner.s_prime,
            _ => panic!("Cannot happen!")
        }
    }
}