use rug::Integer;
use serde::{Serialize, Deserialize};

use crate::{keys::cl03_key::CL03PublicKey, utils::random::random_qr};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bases(pub Vec<Integer>);

impl Bases {
    pub fn generate(pk: &CL03PublicKey, n_attributes: usize) -> Self{
        let mut a_bases: Vec<Integer> = Vec::new();
        for _i in 0..n_attributes {
            let a = random_qr(&pk.N);
            a_bases.push(a);
        }

        Self(a_bases)
    }
}