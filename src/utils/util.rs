
use std::borrow::Borrow;

use bls12_381_plus::{Scalar, G1Projective};
use elliptic_curve::hash2curve::{ExpandMsg, Expander};
use ff::Field;
use crate::bbsplus::ciphersuites::BbsCiphersuite;

pub fn hash_to_scalar<C: BbsCiphersuite>(msg_octects: &[u8], dst: Option<&[u8]>) -> Scalar 
where
    C::Expander: for<'a> ExpandMsg<'a>,
{
    let binding = [C::ID, "H2S_".as_bytes()].concat();
    let default_dst = binding.as_slice();
    let dst = dst.unwrap_or(default_dst);

    let mut counter = 0;
    let mut hashed_scalar = Scalar::from(0);

    let mut uniform_bytes = vec!(0u8; C::EXPAND_LEN);

    let mut msg_prime: Vec<u8>;

    while hashed_scalar == Scalar::from(0) {

        msg_prime = [msg_octects, &[counter; 1][..]].concat();
        C::Expander::expand_message(&[msg_prime.as_slice()], &[dst], C::EXPAND_LEN).unwrap().fill_bytes(&mut uniform_bytes);
        uniform_bytes.reverse();
        hashed_scalar = Scalar::from_okm(uniform_bytes.as_slice().try_into().unwrap());

        counter = counter + 1;

    }

    hashed_scalar
}

pub fn calculate_random_scalars(count: u8) -> Vec<Scalar> {
    let mut rng = rand::thread_rng();
    let mut scalars = Vec::new();
    for _i in 0..count {
        scalars.push(Scalar::random(&mut rng))
    }

    scalars

}

pub fn subgroup_check_g1(p: G1Projective) -> bool {
    if p.is_on_curve().into() && p.is_identity().into() {
        true
    }
    else {
        false
    }
}