//! BlindSign on a Prover-controlled `commitment_with_proof`: no panic, and a commitment that is
//! accepted must re-encode to the same bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use zkryptium::{
    bbsplus::commitment::{BBSplusCommitment, Message},
    keys::pair::KeyPair,
    schemes::{
        algorithms::{BBSplus, BbsBls12381Sha256},
        generics::BlindSignature,
    },
};

type S = BbsBls12381Sha256;
type CS = <S as zkryptium::schemes::algorithms::Scheme>::Ciphersuite;

static KEYPAIR: LazyLock<KeyPair<S>> =
    LazyLock::new(|| KeyPair::<S>::generate(&[42u8; 32], None, None).unwrap());

fuzz_target!(|data: &[u8]| {
    let Some((&n, commitment)) = data.split_first() else { return };
    let messages: Vec<Message> = (0..n % 4).map(|i| Message::hash(vec![i])).collect();
    let commitment = (n & 0x80 == 0).then_some(commitment);
    let (sk, pk) = (KEYPAIR.private_key(), KEYPAIR.public_key());
    let res = BlindSignature::<BBSplus<CS>>::blind_sign(sk, pk, commitment, None, Some(&messages));
    if let (Ok(_), Some(c)) = (res, commitment) {
        if !c.is_empty() {
            assert_eq!(BBSplusCommitment::from_bytes(c).unwrap().to_bytes(), c);
        }
    }
});
