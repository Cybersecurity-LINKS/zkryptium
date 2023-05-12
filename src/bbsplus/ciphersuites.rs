use sha3::Shake256;
use sha2::Sha256;
use elliptic_curve::hash2curve::{ExpandMsg, ExpandMsgXof, ExpandMsgXmd, Expander, ExpanderXmd};
use digest::{HashMarker, OutputSizeUser};


pub trait BbsCiphersuite{
    const ID: &'static [u8];
    const GENERATOR_SEED: &'static [u8];
    const GENERATOR_SEED_BP: &'static [u8];
    const GENERATOR_SEED_DST: &'static [u8];
    const GENERATOR_DST: &'static [u8];
    type HashAlg: HashMarker;
    type Expander: ExpandMsg<'static>;

}


pub struct Bls12381Shake256{}
pub struct Bls12381Sha256 {}




impl BbsCiphersuite for Bls12381Shake256 {
    const ID: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";
    const GENERATOR_SEED: &'static [u8] =  b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_BP: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_BP_MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_DST: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static [u8] = b"BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_SIG_GENERATOR_DST_";
    type HashAlg = Shake256;
    type Expander= ExpandMsgXof<Self::HashAlg>;

}


impl BbsCiphersuite for Bls12381Sha256 {
    const ID: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    const GENERATOR_SEED: &'static [u8] =  b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_BP: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_BP_MESSAGE_GENERATOR_SEED";
    const GENERATOR_SEED_DST: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_GENERATOR_SEED_";
    const GENERATOR_DST: &'static [u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_GENERATOR_DST_";
    type HashAlg = Sha256;
    type Expander= ExpandMsgXmd<Self::HashAlg>;
}

