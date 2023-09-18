// SPDX-FileCopyrightText: 2023 Fondazione LINKS
//
// SPDX-License-Identifier: APACHE-2.0

use std::cmp::Ordering;
use rug::integer::Order;
use rug::{Integer, Complete};
use rug::rand::RandState;
use rand::Rng;


pub fn random_bits(n: u32) -> Integer{
    let mut rng = rand::thread_rng();
    let seed = Integer::from(rng.gen::<u32>());
    let mut rand = RandState::new_mersenne_twister();
    rand.seed(&seed);
    let mut i = Integer::from(Integer::random_bits(n, &mut rand));
    i.set_bit(n-1, true);
    i
}


pub fn random_number(n: Integer) -> Integer {
    let mut rng = rand::thread_rng();
    let seed = Integer::from(rng.gen::<u32>());
    let mut rand = RandState::new_mersenne_twister();
    rand.seed(&seed);
    let number = n.random_below(&mut rand);
    number
}


pub fn random_prime(n: u32) -> Integer {
    let r = random_bits(n);
    let prime = r.next_prime();
    prime
}

pub fn random_qr(n: &Integer) -> Integer{
    let mut r = random_number(n.clone());
    let mut qr = r.secure_pow_mod(&Integer::from(2), n);
    while !(qr.cmp(&Integer::from(1)) == Ordering::Greater && qr.clone().gcd(&n).cmp(&Integer::from(1)) == Ordering::Equal) {
        r = random_number(n.clone());
        qr = r.secure_pow_mod(&Integer::from(2), n);
    }
    qr
}

pub fn rand_int(a: Integer, b: Integer) -> Integer {
    let mut rng = rand::thread_rng();
    let seed = Integer::from(rng.gen::<u32>());
    let mut rand = RandState::new_mersenne_twister();
    rand.seed(&seed);
    let range = (&b - &a).complete() + Integer::from(1);
    // NOTE: return a random integer in the range [a, b], including both end points.
    return a + range.random_below(&mut rand)
}


pub fn generate_nonce() -> Vec<u8>{
    let rand = random_bits(128);
    rand.to_digits(Order::MsfBe)
}