use links_crypto::utils::random;


fn main() {
    let r = random::random_bits(256);
    print!("{}",r);
}