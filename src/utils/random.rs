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

use std::cmp::Ordering;
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