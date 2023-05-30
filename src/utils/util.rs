
use std::borrow::Borrow;

use bls12_381_plus::{Scalar, G1Projective};
use digest::typenum::Pow;
use elliptic_curve::{hash2curve::{ExpandMsg, Expander}, group::Curve};
use ff::Field;
use crate::{bbsplus::ciphersuites::BbsCiphersuite, keys::bbsplus_key::BBSplusPublicKey};

pub fn hash_to_scalar<C: BbsCiphersuite>(msg_octects: &[u8], dst: Option<&[u8]>) -> Scalar 
where
    C::Expander: for<'a> ExpandMsg<'a>,
{
    let binding = [C::ID, "H2S_".as_bytes()].concat();
    let default_dst = binding.as_slice();
    let dst = dst.unwrap_or(default_dst);

    let mut counter: u8 = 0;
    let mut hashed_scalar = Scalar::from(0);

    let mut uniform_bytes = vec!(0u8; C::EXPAND_LEN);

    let mut msg_prime: Vec<u8>;

    while hashed_scalar == Scalar::from(0) {

        msg_prime = [msg_octects, &[counter; 1][..], &[0u8, 0u8, 0u8, 1u8][..]].concat();
        // msg_prime = [msg_octects, &[counter; 1][..]].concat(); //from UPDATED STANDARD
        C::Expander::expand_message(&[msg_prime.as_slice()], &[dst], C::EXPAND_LEN).unwrap().fill_bytes(&mut uniform_bytes);
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
    if p.is_on_curve().into() /*&& p.is_identity().into()*/ {
        true
    }
    else {
        false
    }
}

pub(crate) fn calculate_domain<CS: BbsCiphersuite>(pk: &BBSplusPublicKey, q1: G1Projective, q2: G1Projective, h_points: &[G1Projective], header: Option<&[u8]>) -> Scalar
where
    CS::Expander: for<'a> ExpandMsg<'a>,
{
    let header = header.unwrap_or(b"");

    let L = h_points.len();

    if header.len() > 2usize.pow(64)-1 || L > 2usize.pow(64)-1 {
        panic!("len(header) > 2^64 - 1 or L > 2^64 - 1");
    } 

    let mut dom_octs: Vec<u8> = Vec::new();
    dom_octs.extend_from_slice(&L.to_le_bytes());
    dom_octs.extend_from_slice(&q1.to_affine().to_compressed());
    dom_octs.extend_from_slice(&q2.to_affine().to_compressed());

    h_points.iter().map(|&p| p.to_affine().to_compressed()).for_each(|a| dom_octs.extend_from_slice(&a));

    dom_octs.extend_from_slice(CS::ID);

    let mut dom_input: Vec<u8> = Vec::new();
    dom_input.extend_from_slice(&pk.to_bytes());
    dom_input.extend_from_slice(&dom_octs);

    let header_i2osp: [u8; 8] = (header.len() as u64).to_be_bytes();

    dom_input.extend_from_slice(&header_i2osp);
    dom_input.extend_from_slice(header);

    let domain = hash_to_scalar::<CS>(&dom_input, None);

    domain
}