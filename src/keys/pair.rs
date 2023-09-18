use std::env;
use bls12_381_plus::G2Affine;
use bls12_381_plus::G2Projective;
use bls12_381_plus::Scalar;
use ff::Field;
use hkdf::Hkdf;
use rand::RngCore;
use rug::Integer;
use rug::integer::IsPrime;
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;

use crate::bbsplus::ciphersuites::BbsCiphersuite;
use crate::cl03::ciphersuites::CLCiphersuite;

use crate::schemes::algorithms::BBSplus;
use crate::schemes::algorithms::CL03;
use crate::schemes::algorithms::Scheme;
use crate::utils::random::random_prime;
use crate::utils::random::random_qr;
use super::bbsplus_key::BBSplusPublicKey;
use super::bbsplus_key::BBSplusSecretKey;
use super::cl03_key::CL03PublicKey;
use super::cl03_key::CL03SecretKey;
use sha2::Digest;


#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct KeyPair<S: Scheme>{
    public: S::PubKey,
    private: S::PrivKey,
}

impl <S> KeyPair<S> 
where S: Scheme
{

    pub fn public_key(&self) -> &S::PubKey{
        &self.public
    }

    pub fn private_key(&self) -> &S::PrivKey {
        &self.private
    }

    pub fn write_keypair_to_file(&self, file: Option<String>)
    {
        println!("writhing to file...");

        // #[derive(Deserialize, Serialize, Debug)]
        // #[allow(non_snake_case)]
        // struct FileToWrite {
        //     keyPair: Self
        // }

        // let key_pair_to_write: FileToWrite = FileToWrite { 
        //     keyPair: key_pair
        // };

        let file = file.unwrap_or(String::from("../fixtures/fixture_data/keyPair.json"));
        let current_path = env::current_dir().unwrap();
        let file_to_write = current_path.join(file);

        std::fs::write(
            &file_to_write, 
            serde_json::to_string_pretty(
                &self
            ).expect("failed to serializing key pair")
        ).expect(&format!("failed to write key pair to file: {}", file_to_write.to_str().unwrap()));
    }
}


impl <CS: CLCiphersuite> KeyPair<CL03<CS>>{

    pub fn generate(n_attributes: Option<usize>) -> Self {
        let n = CS::SECPARAM; //SECPARAM
        let mut pprime = random_prime(n);
        let mut p = Integer::from(2) * pprime.clone() + Integer::from(1);
        loop{
            // println!("{} INT", p);
            // let digits = p.to_digits::<u8>(Order::MsfBe);
            // let bignum = BigUint::from_bytes_be(&digits);
            // println!("{} BIGNUM", bignum);
            if p.is_probably_prime(50) !=IsPrime::No {
                break;
            }
            pprime = random_prime(n);
            p = Integer::from(2) * pprime + Integer::from(1);
        }

        let mut qprime = random_prime(n);
        let mut q = Integer::from(2) * qprime.clone() + Integer::from(1);
        loop{
            // println!("{} INT", p);
            // let digits = p.to_digits::<u8>(Order::MsfBe);
            // let bignum = BigUint::from_bytes_be(&digits);
            // println!("{} BIGNUM", bignum);
            if p != q && q.is_probably_prime(100) !=IsPrime::No {
                break;
            }
            qprime = random_prime(n);
            q = Integer::from(2) * qprime + Integer::from(1);
        }

        let N = p.clone() * q.clone();
    
        let mut a_bases: Vec<Integer> = Vec::new();

        let n_attr = n_attributes.unwrap_or(1);
        for _i in 0..n_attr {
            let a = random_qr(&N);
            a_bases.push(a);
        }

        let b = random_qr(&N);
        let c = random_qr(&N);

        let pk = CL03PublicKey::new(N, b, c, a_bases);
        let sk = CL03SecretKey::new(p, q);

        //let pair = CL03KeyPair::new(sk, pk);
        Self{public: pk, private: sk}
        // Self{public: PublicKey::new(PublicKeyData::CL03(pk)), private: PrivateKey::new(PrivateKeyData::CL03(sk)), p: PhantomData}

    }
}

impl <CS: BbsCiphersuite> KeyPair<BBSplus<CS>>{ 
     
    pub fn generate_rng<R: RngCore>(rng: &mut R) -> Self {
        let sk = Scalar::random(rng);
        let pk: G2Projective = G2Affine::generator() * sk;
        // BBSplusKeyPair::new(BBSplusSecretKey(sk), BBSplusPublicKey(pk))

        Self{public: BBSplusPublicKey(pk), private: BBSplusSecretKey(sk)}
    }
    
    pub fn generate<T>(ikm: T, key_info: Option<&[u8]>) -> Self
    where
        T: AsRef<[u8]>
    {
        let ikm = ikm.as_ref();
        let key_info = key_info.unwrap_or(&[]);
        let init_salt = "BBS-SIG-KEYGEN-SALT-".as_bytes();
    
        // if ikm.len() < 32 {
        //     return Err(BadParams { 
        //         cause: format!("Invalid ikm length. Needs to be at least 32 bytes long. Got {}", ikm.len())
        //     })
        // }
    
        // L = ceil((3 * ceil(log2(r))) / 16)
        const L: usize = 48;
        const L_BYTES: [u8; 2] = (L as u16).to_be_bytes();
    
        // salt = H(salt)
        let mut hasher = Sha256::new();
        hasher.update(init_salt);
        let salt = hasher.finalize();
    
        // PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
        let prk = Hkdf::<Sha256>::new(
            Some(&salt),
            &[ikm, &[0u8; 1][..]].concat()
        );
    
        // OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
        let mut okm = [0u8; 64];
    
        prk.expand(
            &[&key_info, &L_BYTES[..]].concat(),
            &mut okm[(64-L)..]
        ).expect(
            &format!("The HKDF-expand output cannot be more than {} bytes long", 255 * Sha256::output_size())
        );
    
        okm.reverse(); // okm is in be format
        let sk = Scalar::from_bytes_wide(&okm);
        let pk: G2Projective = G2Affine::generator() * sk;
        // let pk_affine = pk.to_affine();
    
        // // transform secret key from le to be
        // let mut sk_bytes = sk.to_bytes();
        // sk_bytes.reverse();

        // BBSplusKeyPair::new(BBSplusSecretKey(sk), BBSplusPublicKey(pk))

        Self{public: BBSplusPublicKey(pk), private: BBSplusSecretKey(sk)}
    }

}




