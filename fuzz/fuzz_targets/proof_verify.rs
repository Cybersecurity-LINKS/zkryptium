//! BBS and Blind BBS proof verification on a Prover-controlled presentation: the proof bytes
//! and the disclosure choices come from the input. No panic, and nothing but a genuine
//! test-vector presentation may verify.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;
use zkryptium::{
    bbsplus::{
        commitment::Message,
        keys::BBSplusPublicKey,
        proof::{BlindProofVerifyInput, Disclosure},
    },
    schemes::{
        algorithms::{BBSplus, BbsBls12381Sha256},
        generics::{BlindPoKSignature, PoKSignature},
    },
};

type S = BbsBls12381Sha256;
type CS = <S as zkryptium::schemes::algorithms::Scheme>::Ciphersuite;

// fixture_data/fixture_data/bls12-381-sha-256/proof/proof003.json
const PK: &str = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c";
const HEADER: &str = "11223344556677889900aabbccddeeff";
const PH: &str = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501";
const MESSAGES: [&str; 10] = [
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
    "496694774c5604ab1b2544eababcf0f53278ff50",
    "515ae153e22aae04ad16f759e07237b4",
    "d183ddc6e2665aa4e2f088af",
    "ac55fb33a75909ed",
    "96012096",
    "",
];

struct Ctx {
    pk: BBSplusPublicKey,
    header: Vec<u8>,
    ph: Vec<u8>,
    messages: Vec<Vec<u8>>,
    /// (proof, disclosed indexes) of the valid test vectors signed under `PK`.
    genuine: Vec<(String, Vec<usize>)>,
    /// Proofs of the valid Blind BBS test vectors signed under `PK`.
    genuine_blind: Vec<String>,
}

fn genuine_blind_proofs() -> Vec<String> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixture_data/fixture_data_blind/bls12-381-sha-256/proof");
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let j: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(e.unwrap().path()).unwrap()).unwrap();
            (j["result"]["valid"] == true && j["signerPublicKey"] == PK)
                .then(|| j["proof"].as_str().unwrap().to_owned())
        })
        .collect()
}

fn genuine_proofs() -> Vec<(String, Vec<usize>)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../fixture_data/fixture_data/bls12-381-sha-256/proof");
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let j: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(e.unwrap().path()).unwrap()).unwrap();
            (j["result"]["valid"] == true && j["signerPublicKey"] == PK).then(|| {
                let idx = j["disclosedIndexes"].as_array().unwrap();
                (
                    j["proof"].as_str().unwrap().to_owned(),
                    idx.iter().map(|i| i.as_u64().unwrap() as usize).collect(),
                )
            })
        })
        .collect()
}

static CTX: LazyLock<Ctx> = LazyLock::new(|| Ctx {
    pk: BBSplusPublicKey::from_bytes(&hex::decode(PK).unwrap()).unwrap(),
    header: hex::decode(HEADER).unwrap(),
    ph: hex::decode(PH).unwrap(),
    messages: MESSAGES.iter().map(|m| hex::decode(m).unwrap()).collect(),
    genuine: genuine_proofs(),
    genuine_blind: genuine_blind_proofs(),
});

fuzz_target!(|data: &[u8]| {
    // Header: mode, total messages, issuer messages, 4 bytes of disclosure bits.
    if data.len() < 7 {
        return;
    }
    let ctx = &*CTX;
    let (head, proof_bytes) = data.split_at(7);
    let mode = head[0];
    let bits = u32::from_le_bytes(head[3..7].try_into().unwrap());

    if mode % 2 == 0 {
        // BBS: up to 16 disclosed indexes from a bitmask over 0..16 (only 0..10 are messages).
        let mask = bits as u16;
        let indexes: Vec<usize> = (0..16).filter(|i| mask >> i & 1 == 1).collect();
        let msgs: Vec<Vec<u8>> = indexes
            .iter()
            .map(|&i| ctx.messages.get(i).cloned().unwrap_or_default())
            .collect();
        // Optionally drop a message to test count mismatches.
        let msgs = if mode & 0x80 != 0 && !msgs.is_empty() { msgs[1..].to_vec() } else { msgs };
        let Ok(proof) = PoKSignature::<S>::from_bytes(proof_bytes) else { return };
        let res = proof.proof_verify(&ctx.pk, Some(&msgs), Some(&indexes), Some(&ctx.header), Some(&ctx.ph));
        if res.is_ok() {
            assert!(mode & 0x80 == 0);
            let presented = (hex::encode(proof_bytes), indexes);
            assert!(ctx.genuine.contains(&presented), "non-genuine proof verified: {presented:?}");
        }
    } else {
        // Blind BBS: 2 bits per message, up to 16 messages; L issuer messages, the rest blind.
        let total = head[1] as usize % 17;
        let issuer_known = (head[2] as usize).min(total);
        let disclosures: Vec<Disclosure> = (0..total)
            .map(|i| match bits >> (2 * i) & 3 {
                0 => Disclosure::Disclose,
                1 => Disclosure::Commit,
                _ => Disclosure::Hide,
            })
            .collect();
        let commitments = disclosures.iter().filter(|d| **d == Disclosure::Commit).count();
        let disclosed: Vec<Message> = disclosures
            .iter()
            .enumerate()
            .filter(|(_, d)| **d == Disclosure::Disclose)
            .map(|(i, _)| Message::hash(ctx.messages[i % 10].clone()))
            .collect();
        let Ok(proof) = BlindPoKSignature::<BBSplus<CS>>::from_bytes(proof_bytes, commitments) else {
            return;
        };
        let res = proof.blind_proof_verify(
            &ctx.pk,
            BlindProofVerifyInput {
                header: Some(&ctx.header),
                ph: Some(&ctx.ph),
                issuer_known_messages_no: issuer_known,
                disclosed_messages: &disclosed,
                message_disclosures: &disclosures,
            },
        );
        if res.is_ok() {
            let presented = hex::encode(proof_bytes);
            assert!(ctx.genuine_blind.contains(&presented), "non-genuine blind proof verified: {presented}");
        }
    }
});
