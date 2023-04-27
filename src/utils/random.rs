use std::cmp::Ordering;
use std::time::Instant;
use glass_pumpkin::safe_prime;
use glass_pumpkin::prime;
use num_primes::Generator;

// use gmp::mpz::{Mpz, ProbabPrimeResult};
// use gmp::rand::RandState;
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use num_prime::{nt_funcs::{next_prime, is_prime}, PrimalityTestConfig, Primality, buffer::NaiveBuffer};
use rug::Integer;
use rug::integer::{IsPrime, Order};
use rug::rand::RandState;
use rand::Rng;

// pub fn random_bits(n: &u64) -> BigUint{
//     let mut rng = thread_rng();
//     let mut r: BigUint = rng.gen_biguint(n.clone());
//     r.set_bit(n-1, true);
//     r
// }

// pub fn random_bits_gmp(n: &u64) -> Mpz{
//     let mut r = RandState::new();

//     let mut random = r.urandom_2exp(n.clone());
//     random.setbit((n-1).try_into().unwrap());
//     random
// }

pub fn random_bits(n: u32) -> Integer{
    let mut rng = rand::thread_rng();
    let seed = Integer::from(rng.gen::<u32>());
    let mut rand = RandState::new_mersenne_twister();
    rand.seed(&seed);
    let mut i = Integer::from(Integer::random_bits(n, &mut rand));
    i.set_bit(n-1, true);
    i
}



// pub fn random_number(n: &BigUint) -> BigUint{
//     let mut rng = thread_rng();
//     let r: BigUint = rng.gen_biguint_below(&n);
//     r
// }

pub fn random_number(n: Integer) -> Integer {
    let mut rng = rand::thread_rng();
    let seed = Integer::from(rng.gen::<u32>());
    let mut rand = RandState::new_mersenne_twister();
    let number = n.random_below(&mut rand);
    number
}

// pub fn random_number_gmp(n: &Mpz) -> Mpz {
//     let mut r = RandState::new();

//     let mut random = r.urandom(n);

//     random
// }

// pub fn random_prime_gmp(n: &u64) -> Mpz{
//     let r = random_bits_gmp(n);
//     let mut prime: Mpz;
//     loop {
//         prime = r.nextprime();
//         if prime.probab_prime(25) == ProbabPrimeResult::Prime {
//             break;
//         }
//     }

//     prime
// }



// pub fn random_prime(n: &u64) -> BigUint {
//     let write_data_start_time = Instant::now();
//     let r = random_bits(n);
//     println!("Random_bits {:.2?}", write_data_start_time.elapsed());
//     let mut prime: BigUint;
//     let mut p: Option<BigUint>;
//     p = next_prime(&r, None);
//     prime = p.unwrap();
//     println!("Random {:.2?}", write_data_start_time.elapsed());
//     prime
// }

pub fn random_prime(n: u32) -> Integer {
    let r = random_bits(n);
    let prime = r.next_prime();
    prime
}

// pub fn random_prime(n: &u64) -> BigUint {
//     let write_data_start_time = Instant::now();
//     let mut prime: BigUint;
//     prime = safe_prime::new(usize::try_from(n.clone()).unwrap()).unwrap();
//     println!("Random {:.2?}", write_data_start_time.elapsed());
//     prime
// }

// pub fn random_prime(n: &u64) -> BigUint {
//     let write_data_start_time = Instant::now();
//     let prime: num_bigint::BigUint = prime::new(512).unwrap();
//     println!("Random {:.2?}", write_data_start_time.elapsed());

//     prime
// }


// pub fn random_qr(n: &Integer) -> Integer{
//     let mut r = random_number(n);
//     let mut qr = r.modpow(&2.to_biguint().unwrap(), &n);
//     while !(qr.cmp(&1.to_biguint().unwrap()) == Ordering::Greater && qr.gcd(&n).cmp(&1.to_biguint().unwrap()) == Ordering::Equal) {
//         r = random_number(n);
//         qr = r.modpow(&2.to_biguint().unwrap(), &n);
//     }
//     qr
// }

pub fn random_qr(n: &Integer) -> Integer{
    let mut r = random_number(n.clone());
    let mut qr = r.secure_pow_mod(&Integer::from(2), n);
    while !(qr.cmp(&Integer::from(1)) == Ordering::Greater && qr.clone().gcd(&n).cmp(&Integer::from(1)) == Ordering::Equal) {
        r = random_number(n.clone());
        qr = r.secure_pow_mod(&Integer::from(2), n);
    }
    qr
}

// pub fn random_qr_gmp(n: &Mpz) -> Mpz {
//     let mut r = random_number_gmp(n);

//     let mut qr = r.powm_sec(&Mpz::from(2), n);
//     while !(qr.gt(&Mpz::from(1)) && qr.gcd(&n).cmp(&Mpz::from(1)) == Ordering::Equal) {
//         r = random_number_gmp(n);
//         qr = r.powm_sec(&Mpz::from(2), n);
//     }

//     qr

// }