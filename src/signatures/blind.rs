use std::marker::PhantomData;

use bls12_381_plus::{G1Projective, Scalar, G1Affine};
use elliptic_curve::{group::Curve, subtle::{CtOption, Choice}};
use rug::{Integer, ops::Pow};
use serde::{Deserialize, Serialize};

use crate::{schemes::algorithms::{Scheme, BBSplus, CL03}, bbsplus::ciphersuites::BbsCiphersuite, cl03::ciphersuites::CLCiphersuite, keys::cl03_key::{CL03PublicKey, CL03SecretKey}, utils::random::{random_prime, random_bits}};

use super::commitment::CL03Commitment;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BBSplusBlindSignature {
    pub(crate) a: G1Projective,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}

impl BBSplusBlindSignature {
    const BYTES: usize = 112;

    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; Self::BYTES];
        bytes[0..48].copy_from_slice(&self.a.to_affine().to_compressed());
        let mut e = self.e.to_bytes();
        e.reverse();
        bytes[48..80].copy_from_slice(&e[..]);
        let mut s = self.s.to_bytes();
        s.reverse();
        bytes[80..112].copy_from_slice(&s[..]);
        bytes
    }

    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        let aa = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[0..48]).unwrap())
            .map(G1Projective::from);
        let mut e_bytes = <[u8; 32]>::try_from(&data[48..80]).unwrap();
        e_bytes.reverse();
        let ee = Scalar::from_bytes(&e_bytes);
        let mut s_bytes = <[u8; 32]>::try_from(&data[80..112]).unwrap();
        s_bytes.reverse();
        let ss = Scalar::from_bytes(&s_bytes);

        aa.and_then(|a| {
            ee.and_then(|e| ss.and_then(|s| CtOption::new(Self{ a, e, s }, Choice::from(1))))
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CL03BlindSignature {
    pub(crate) e: Integer,
    pub(crate) rprime: Integer,
    pub(crate) v: Integer,
}

impl CL03BlindSignature {
    pub fn to_bytes(&self){

    }

    pub fn from_bytes() {

    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BlindSignature<S: Scheme> {
    value: Vec<u8>,
    _p: PhantomData<S>
}

impl <CS: BbsCiphersuite> BlindSignature<BBSplus<CS>> {

}

impl <CS: CLCiphersuite> BlindSignature<CL03<CS>> {
    pub fn blind_sign(pk: &CL03PublicKey, sk: &CL03SecretKey, commitment: CL03Commitment) -> Self{
        let mut e = random_prime(CS::le);
        let phi_n = (sk.p-1)*(sk.q-1);

        while ((e > 2.pow(CS::le-1)) && (e < 2.pow(CS::le)) && (Integer::gcd(e, phi_n) == 1)) == false {
            e = random_prime(CS::le.try_into().unwrap());
        }

        let rprime = random_bits(CS::ls);
        let e2n = e.invert(phi_n).unwrap();

        // v = powmod(((Cx) * powmod(pk['b'], rprime, pk['N']) * pk['c']), e2n, pk['N'])
        let v = ((commitment.value * pk.b.pow_mod(&rprime, &pk.N).unwrap()) * pk.c).pow_mod(&e2n, &pk.N).unwrap();
        let sig = CL03BlindSignature{e, rprime, v};
        // sig = { 'e':e, 'rprime':rprime, 'v':v }

    }
}



