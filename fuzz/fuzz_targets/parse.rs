//! Every BBS+ byte parser on untrusted input: no panic, and whatever is accepted is a
//! canonical encoding (serializing it again gives back the same bytes).
#![no_main]

use libfuzzer_sys::fuzz_target;
use zkryptium::bbsplus::{
    commitment::{BBSplusCommitment, BlindFactor},
    keys::{BBSplusPublicKey, BBSplusSecretKey},
    proof::{BBSplusBlindPoKSignature, BBSplusPoKSignature, BBSplusZKPoK},
    pseudonym::{BBSplusPseudonym, PseudonymSecret},
    signature::BBSplusSignature,
};
use zkryptium::utils::message::bbsplus_message::BBSplusMessage;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, data)) = data.split_first() else { return };
    match selector % 10 {
        0 => {
            if let Ok(p) = BBSplusPoKSignature::from_bytes(data) {
                assert_eq!(p.to_bytes(), data);
            }
        }
        1 => {
            // First byte: number of commitments. High values exercise the length overflow checks.
            let Some((&n, data)) = data.split_first() else { return };
            let n = if n >= 0xF0 { usize::MAX - (n as usize & 0x0F) } else { n as usize % 8 };
            if let Ok(p) = BBSplusBlindPoKSignature::from_bytes(data, n) {
                assert_eq!(p.to_bytes(), data);
                assert_eq!(p.commitments().len(), n);
            }
        }
        2 => {
            if let Ok(c) = BBSplusCommitment::from_bytes(data) {
                assert_eq!(c.to_bytes(), data);
            }
        }
        3 => {
            if let Ok(z) = BBSplusZKPoK::from_bytes(data) {
                assert_eq!(z.to_bytes(), data);
            }
        }
        4 => {
            if let Ok(pk) = BBSplusPublicKey::from_bytes(data) {
                assert_eq!(pk.to_bytes().as_slice(), data);
            }
            if let (Ok(x), Ok(y)) = (data.get(..96).unwrap_or(&[]).try_into(), data.get(96..192).unwrap_or(&[]).try_into()) {
                let _ = BBSplusPublicKey::from_coordinates(x, y);
            }
        }
        5 => {
            if let Ok(sk) = BBSplusSecretKey::from_bytes(data) {
                assert_eq!(sk.to_bytes().as_slice(), data);
            }
        }
        6 => {
            if let Ok(arr) = data.try_into() {
                if let Ok(s) = BBSplusSignature::from_bytes(arr) {
                    assert_eq!(s.to_bytes().as_slice(), data);
                }
            }
        }
        7 => {
            if let Ok(p) = BBSplusPseudonym::from_bytes(data) {
                assert_eq!(p.to_bytes(), data);
            }
        }
        8 => {
            if let Ok(arr) = <&[u8; 32]>::try_from(data) {
                if let Ok(s) = PseudonymSecret::from_bytes(arr) {
                    assert_eq!(&s.to_bytes(), arr);
                }
                if let Ok(b) = BlindFactor::from_bytes(arr) {
                    assert_eq!(&b.to_bytes(), arr);
                }
                if let Ok(m) = BBSplusMessage::from_bytes_be(arr) {
                    assert_eq!(&m.to_bytes_be(), arr);
                }
            }
        }
        _ => {
            if let Ok(s) = std::str::from_utf8(data) {
                if let Ok(secret) = PseudonymSecret::from_hex(s) {
                    assert_eq!(hex::encode(secret.to_bytes()), s.to_ascii_lowercase());
                }
            }
        }
    }
});
