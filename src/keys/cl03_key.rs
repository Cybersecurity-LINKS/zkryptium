use std::{iter::Map, collections::HashMap};
use glass_pumpkin::safe_prime;
// use gmp::mpz::{Mpz, ProbabPrimeResult};
use num_bigint::{BigUint, ToBigUint};
use num_prime::{nt_funcs::is_prime, PrimalityTestConfig};
use num_primes::Verification;
use rug::{Integer, integer::IsPrime};

use crate::{keys::pair::KeyPair, utils::random::{random_prime, random_qr}};

// use super::key::PrivateKey;

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CL03PublicKey{
    N: Integer,
    b: Integer,
    c: Integer,
    a_bases: Vec<Integer>
}

impl CL03PublicKey {
    pub fn new(N: Integer, b: Integer, c: Integer, a_bases: Vec<Integer>) -> Self {
        Self{N, b, c, a_bases}
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CL03SecretKey{
    p: Integer,
    q: Integer
    
}

impl CL03SecretKey{
    pub fn new(p: Integer, q: Integer) -> Self {
        Self { p, q}
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CL03KeyPair {
    private: CL03SecretKey,
    public: CL03PublicKey
}



impl CL03KeyPair{

    // fn generate() -> Self {

    //     let n = 512; //SECPARAM
    //     let mut pprime = random_prime(n);
    //     let mut p = Integer::from(2) * pprime.clone() + Integer::from(1);
    //     loop{
    //         // println!("{} INT", p);
    //         // let digits = p.to_digits::<u8>(Order::MsfBe);
    //         // let bignum = BigUint::from_bytes_be(&digits);
    //         // println!("{} BIGNUM", bignum);
    //         if p.is_probably_prime(50) !=IsPrime::No {
    //             break;
    //         }
    //         pprime = random_prime(n);
    //         p = Integer::from(2) * pprime + Integer::from(1);
    //     }

    //     let mut qprime = random_prime(n);
    //     let mut q = Integer::from(2) * qprime.clone() + Integer::from(1);
    //     loop{
    //         // println!("{} INT", p);
    //         // let digits = p.to_digits::<u8>(Order::MsfBe);
    //         // let bignum = BigUint::from_bytes_be(&digits);
    //         // println!("{} BIGNUM", bignum);
    //         if p != q && q.is_probably_prime(100) !=IsPrime::No {
    //             break;
    //         }
    //         qprime = random_prime(n);
    //         q = Integer::from(2) * qprime + Integer::from(1);
    //     }

    //     let N = p.clone() * q.clone();
    
    //     let mut a_bases: Vec<Integer> = Vec::new();
    //     let a0 = random_qr(&N);

    //     a_bases.push(a0);

    //     let b = random_qr(&N);
    //     let c = random_qr(&N);

    //     let pk = CL03PublicKey{N, b, c, a_bases};
    //     let sk = CL03SecretKey{p, q};

    //     Self{private: sk, public: pk}

    // }

    pub fn new(private: CL03SecretKey, public: CL03PublicKey) -> Self{
        Self{private, public}
    }

    pub fn private(&self) -> &CL03SecretKey{
        &self.private
    }

    pub fn public(&self) -> &CL03PublicKey{
        &self.public
    }
}



// #[derive(Clone, PartialEq, Eq, Hash, Debug)]
// pub struct CL03PublicKey{
//     N: Mpz,
//     b: Mpz,
//     c: Mpz,
//     a_bases: Vec<Mpz>
// }

// #[derive(Clone, PartialEq, Eq, Hash, Debug)]
// pub struct CL03SecretKey{
//     p: Mpz,
//     q: Mpz
    
// }

// #[derive(Clone, PartialEq, Eq, Hash, Debug)]
// pub struct CL03KeyPair {
//     private: CL03SecretKey,
//     public: CL03PublicKey
// }

// impl KeyPair for CL03KeyPair{
//     type PublicKey = CL03PublicKey;
//     type PrivateKey = CL03SecretKey;
    
//     fn new() -> Self {

//         let k = 512; //SECPARAM
//         let mut pprime: Mpz;
//         let mut p: Mpz;
//         loop {
//             pprime = random_prime_gmp(&k);
//             p =  Mpz::from(2) * pprime + Mpz::from(1);
//             if p.probab_prime(25) == ProbabPrimeResult::Prime {
//                 break;
//             }
//         }

//         let mut qprime: Mpz;
//         let mut q: Mpz;
//         loop {
//             qprime = random_prime_gmp(&k);
//             q =  Mpz::from(2) * qprime + Mpz::from(1);
//             if q.probab_prime(25) == ProbabPrimeResult::Prime {
//                 break;
//             }
//         }

//         let N = &p * &q;

//         let mut a_bases: Vec<Mpz> = Vec::new();
//         let a0 = random_qr_gmp(&N);

//         a_bases.push(a0);

//         let b = random_qr_gmp(&N);
//         let c = random_qr_gmp(&N);

//         let pk = CL03PublicKey{N, b, c, a_bases};
//         let sk = CL03SecretKey{p,q};

//         Self{private: sk, public: pk}

//     }
// }