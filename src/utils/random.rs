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

use rand::Rng;
use rug::rand::{RandGen, RandState};
use rug::{Complete, Integer};
use std::cmp::Ordering;
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

struct CryptographicallySecurePRNG(ChaCha20Rng);

impl RandGen for CryptographicallySecurePRNG {
    fn gen(&mut self) -> u32 {
        self.0.next_u32()
    }
}

/// Generates a random integer with the specified number of bits.
pub fn random_bits(n: u32) -> Integer {

    let mut rng = rand::thread_rng();
    let seed = rng.gen();
    let mut binding = CryptographicallySecurePRNG(ChaCha20Rng::from_seed(seed));
    let mut rand = RandState::new_custom(&mut binding);

    let mut i = Integer::from(Integer::random_bits(n, &mut rand));
    i.set_bit(n - 1, true);
    i
}

/// Generates a random integer less than the specified integer.
pub fn random_number(n: Integer) -> Integer {

    let mut rng = rand::thread_rng();
    let seed = rng.gen();
    let mut binding = CryptographicallySecurePRNG(ChaCha20Rng::from_seed(seed));
    let mut rand = RandState::new_custom(&mut binding);

    let number = n.random_below(&mut rand);
    number
}

/// Generates a random prime number with the specified number of bits.
pub fn random_prime(n: u32) -> Integer {
    let r = random_bits(n);
    let prime = r.next_prime();
    prime
}

/// Generates a random quadratic residue modulo n.
pub fn random_qr(n: &Integer) -> Integer {
    let mut r = random_number(n.clone());
    let mut qr = r.secure_pow_mod(&Integer::from(2), n);
    while !(qr.cmp(&Integer::from(1)) == Ordering::Greater
        && qr.clone().gcd(&n).cmp(&Integer::from(1)) == Ordering::Equal)
    {
        r = random_number(n.clone());
        qr = r.secure_pow_mod(&Integer::from(2), n);
    }
    qr
}

/// Generates a random integer in the range [a, b].
pub fn rand_int(a: Integer, b: Integer) -> Integer {

    let mut rng = rand::thread_rng();
    let seed = rng.gen();
    let mut binding = CryptographicallySecurePRNG(ChaCha20Rng::from_seed(seed));
    let mut rand = RandState::new_custom(&mut binding);

    let range = (&b - &a).complete() + Integer::from(1);
    // NOTE: return a random integer in the range [a, b], including both end points.
    return a + range.random_below(&mut rand);
}
