use std::time::Instant;

use links_crypto::{utils::random, keys::{cl03_key::CL03KeyPair, pair::KeyPair, bbsplus_key::BBSplusKeyPair}};


fn main() {
    let write_data_start_time = Instant::now();
    
    let cl03_keypair = KeyPair::<CL03KeyPair>::generate();
    let bbsplus_keypair = KeyPair::<BBSplusKeyPair>::generate(true);


    println!("Create Key {:.2?}", write_data_start_time.elapsed());

    print!("{:?}", cl03_keypair);
}