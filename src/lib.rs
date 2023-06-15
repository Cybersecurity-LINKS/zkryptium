#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]


pub mod utils;
pub mod keys;
pub mod signatures;
pub mod schemes;
pub mod bbsplus;
pub mod cl03;
pub mod tests;


#[cfg(test)]
mod bbsplus_tests {
    use crate::{schemes::algorithms::{BBSplusSha256, BBSplusShake256}, tests::{map_message_to_scalar_as_hash, message_generators}};

    #[test]
    fn map_message_to_scalar_as_hash_sha256() {
        map_message_to_scalar_as_hash::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json");
    }

    #[test]
    fn map_message_to_scalar_as_hash_shake256() {
        map_message_to_scalar_as_hash::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/MapMessageToScalarAsHash.json");
    }

    #[test]
    fn message_generators_sha256() {
        message_generators::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/generators.json");
    }

    #[test]
    fn prova_bbs() {
        println!("BBSplus");
    }
}


#[cfg(test)]
mod cl03_tests {
    #[test]
    fn prova_cl() {
        println!("CL03");
    }
}