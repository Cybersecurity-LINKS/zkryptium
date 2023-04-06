use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

pub fn random_bits(n: u64) -> BigUint{

    let mut rng = thread_rng();
    let r: BigUint = rng.gen_biguint(n);
    r
    
}