#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]


pub mod utils;
pub mod keys;
pub mod signatures;
pub mod schemes;
pub mod bbsplus;
pub mod cl03;
pub mod tests;


#[cfg(test)]
mod bbsplus_tests {
    use crate::{schemes::algorithms::{BBSplusSha256, BBSplusShake256}, tests::{map_message_to_scalar_as_hash, message_generators, msg_signature, h2s, mocked_rng, proof_check, key_pair_gen}};

    //KEYPAIR
    
    #[test]
    fn keypair() {
        key_pair_gen::<BBSplusSha256>("./fixture_data/keyPair.json");
    }


    //MAP MESSAGE TO SCALAR - SHA256

    #[test]
    fn map_message_to_scalar_as_hash_sha256() {
        map_message_to_scalar_as_hash::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/MapMessageToScalarAsHash.json");
    }

    //MAP MESSAGE TO SCALAR - SHAKE256

    #[test]
    fn map_message_to_scalar_as_hash_shake256() {
        map_message_to_scalar_as_hash::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/MapMessageToScalarAsHash.json");
    }


    //GENERATORS - SHA256
    #[test]
    fn message_generators_sha256() {
        message_generators::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/generators.json");
    }

    //GENERATORS - SHAKE256

    #[test]
    fn message_generators_shake256() {
        message_generators::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/generators.json");
    }


    //MSG SIGNATURE
    #[test]
    fn msg_signature_sha256_1() {
        msg_signature::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature001.json");
    }
    #[test]
    fn msg_signature_sha256_2() {
        msg_signature::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature002.json");
    }
    #[test]
    fn msg_signature_sha256_3() {
        msg_signature::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature003.json");
    }
    #[test]
    fn msg_signature_sha256_4() {
        msg_signature::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json");
    }
    #[test]
    fn msg_signature_sha256_5() {
        msg_signature::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature005.json");
    }
    #[test]
    fn msg_signature_sha256_6() {
        msg_signature::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature006.json");
    }
    #[test]
    fn msg_signature_sha256_7() {
        msg_signature::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature007.json");
    }
    #[test]
    fn msg_signature_sha256_8() {
        msg_signature::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature008.json");
    }
    #[test]
    fn msg_signature_sha256_9() {
        msg_signature::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature009.json");
    }


    //MSG SIGNATURE - SHAKE256
    #[test]
    fn msg_signature_shake256_1() {
        msg_signature::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature001.json");
    }
    #[test]
    fn msg_signature_shake256_2() {
        msg_signature::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature002.json");
    }
    #[test]
    fn msg_signature_shake256_3() {
        msg_signature::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature003.json");
    }
    #[test]
    fn msg_signature_shake256_4() {
        msg_signature::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json");
    }
    #[test]
    fn msg_signature_shake256_5() {
        msg_signature::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature005.json");
    }
    #[test]
    fn msg_signature_shake256_6() {
        msg_signature::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature006.json");
    }
    #[test]
    fn msg_signature_shake256_7() {
        msg_signature::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature007.json");
    }
    #[test]
    fn msg_signature_shake256_8() {
        msg_signature::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature008.json");
    }
    #[test]
    fn msg_signature_shake256_9() {
        msg_signature::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature009.json");
    }

    //h2s - SHA256
    #[test]
    fn h2s_sha256_1() {
        h2s::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "h2s/h2s001.json");
    }
    #[test]
    fn h2s_sha256_2() {
        h2s::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "h2s/h2s002.json");
    }

    //h2s - SHAKE256
    #[test]
    fn h2s_shake256_1() {
        h2s::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "h2s/h2s001.json");
    }
    #[test]
    fn h2s_shake256_2() {
        h2s::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "h2s/h2s002.json");
    }

    const SEED: &str = "332e313431353932363533353839373933323338343632363433333833323739";

    //mocked_rng - SHA256
    #[test]
    fn mocked_rng_sha256() {
        mocked_rng::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "mockedRng.json", SEED);
    }

    //mocked_rng - SHAKE256
    #[test]
    fn mocked_rng_shake256() {
        mocked_rng::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "mockedRng.json", SEED);
    }



    //SIGNATURE POK - SHA256
    #[test]
    fn proof_check_sha256_1() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature001.json", "proof/proof001.json", SEED)
    }
    #[test]
    fn proof_check_sha256_2() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof002.json", SEED)
    }
    #[test]
    fn proof_check_sha256_3() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof003.json", SEED)
    }
    #[test]
    fn proof_check_sha256_4() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof004.json", SEED)
    }
    #[test]
    fn proof_check_sha256_5() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof005.json", SEED)
    }
    #[test]
    fn proof_check_sha256_6() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof006.json", SEED)
    }
    #[test]
    fn proof_check_sha256_7() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof007.json", SEED)
    }
    #[test]
    fn proof_check_sha256_8() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof008.json", SEED)
    }
    #[test]
    fn proof_check_sha256_9() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof009.json", SEED)
    }
    #[test]
    fn proof_check_sha256_10() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof010.json", SEED)
    }
    #[test]
    fn proof_check_sha256_11() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof011.json", SEED)
    }
    #[test]
    fn proof_check_sha256_12() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof012.json", SEED)
    }
    #[test]
    fn proof_check_sha256_13() {
        proof_check::<BBSplusSha256>("./fixture_data/bls12-381-sha-256/", "signature/signature004.json", "proof/proof013.json", SEED)
    }



    //SIGNATURE POK - SHAKE256

    #[test]
    fn proof_check_shake256_1() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature001.json", "proof/proof001.json", SEED)
    }
    #[test]
    fn proof_check_shake256_2() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof002.json", SEED)
    }
    #[test]
    fn proof_check_shake256_3() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof003.json", SEED)
    }
    #[test]
    fn proof_check_shake256_4() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof004.json", SEED)
    }
    #[test]
    fn proof_check_shake256_5() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof005.json", SEED)
    }
    #[test]
    fn proof_check_shake256_6() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof006.json", SEED)
    }
    #[test]
    fn proof_check_shake256_7() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof007.json", SEED)
    }
    #[test]
    fn proof_check_shake256_8() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof008.json", SEED)
    }
    #[test]
    fn proof_check_shake256_9() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof009.json", SEED)
    }
    #[test]
    fn proof_check_shake256_10() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof010.json", SEED)
    }
    #[test]
    fn proof_check_shake256_11() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof011.json", SEED)
    }
    #[test]
    fn proof_check_shake256_12() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof012.json", SEED)
    }
    #[test]
    fn proof_check_shake256_13() {
        proof_check::<BBSplusShake256>("./fixture_data/bls12-381-shake-256/", "signature/signature004.json", "proof/proof013.json", SEED)
    }

}


#[cfg(test)]
mod cl03_tests {
    #[test]
    fn prova_cl() {
        println!("CL03");
    }
}