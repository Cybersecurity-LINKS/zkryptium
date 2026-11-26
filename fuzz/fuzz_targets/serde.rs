//! serde (JSON) decoding of the BBS+ types bypasses `from_bytes`: whatever it accepts must not
//! make the verification panic, and a decoded proof must never verify (no presentation for
//! this key exists).
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use zkryptium::{
    bbsplus::{
        commitment::{BBSplusCommitment, Message},
        keys::BBSplusPublicKey,
        proof::{BlindProofVerifyInput, Disclosure},
        pseudonym::BBSplusPseudonym,
    },
    keys::pair::KeyPair,
    schemes::{
        algorithms::{BBSplus, BbsBls12381Sha256},
        generics::{BlindPoKSignature, PoKSignature, Signature},
    },
};

type S = BbsBls12381Sha256;
type CS = <S as zkryptium::schemes::algorithms::Scheme>::Ciphersuite;

static KEYPAIR: LazyLock<KeyPair<S>> =
    LazyLock::new(|| KeyPair::<S>::generate(&[7u8; 32], None, None).unwrap());

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let pk = KEYPAIR.public_key();
    let msgs: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];

    if let Ok(k) = serde_json::from_str::<BBSplusPublicKey>(s) {
        let _ = k.to_bytes();
    }
    let _ = serde_json::from_str::<BBSplusCommitment>(s);
    let _ = serde_json::from_str::<BBSplusPseudonym>(s);
    if let Ok(sig) = serde_json::from_str::<Signature<S>>(s) {
        assert!(sig.verify(pk, Some(&msgs), None).is_err());
    }
    if let Ok(proof) = serde_json::from_str::<PoKSignature<S>>(s) {
        let _ = proof.to_bytes();
        assert!(proof.proof_verify(pk, Some(&msgs[..1]), Some(&[0]), None, None).is_err());
        assert!(proof.proof_verify(pk, None, None, None, None).is_err());
    }
    if let Ok(proof) = serde_json::from_str::<BlindPoKSignature<BBSplus<CS>>>(s) {
        let _ = proof.to_bytes();
        let disclosed = [Message::hash(b"a".to_vec())];
        let res = proof.blind_proof_verify(
            pk,
            BlindProofVerifyInput {
                header: None,
                ph: None,
                issuer_known_messages_no: 2,
                disclosed_messages: &disclosed,
                message_disclosures: &[Disclosure::Disclose, Disclosure::Commit],
            },
        );
        assert!(res.is_err());
    }
});
