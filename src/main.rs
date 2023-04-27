use std::time::Instant;

use links_crypto::{utils::random, keys::{cl03_key::CL03KeyPair, pair::KeyPair}};


fn main() {
    let write_data_start_time = Instant::now();
    
    let cl03_keypair = CL03KeyPair::new();
    println!("Create Key {:.2?}", write_data_start_time.elapsed());

    print!("{:?}", cl03_keypair);
}