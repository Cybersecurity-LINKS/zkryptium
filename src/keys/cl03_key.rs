use rug::{Integer, integer::IsPrime};
use serde::{Serialize, Deserialize};
use crate::{utils::random::{random_prime, random_qr, random_number}, cl03::ciphersuites::CLCiphersuite};


#[derive(Clone, PartialEq, PartialOrd, Eq, Hash, Debug, Ord, Serialize, Deserialize)]
pub struct CL03PublicKey{
    pub N: Integer,
    pub b: Integer,
    pub c: Integer,
    pub a_bases: Vec<(Integer, bool)>
}

impl CL03PublicKey {
    pub fn new(N: Integer, b: Integer, c: Integer, a_bases: Vec<(Integer, bool)>) -> Self {
        Self{N, b, c, a_bases}
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct CL03SecretKey{
    pub p: Integer,
    pub q: Integer
    
}

impl CL03SecretKey{
    pub fn new(p: Integer, q: Integer) -> Self {
        Self { p, q}
    }
}


pub struct CL03CommitmentPublicKey {
    pub N: Integer,
    pub h: Integer,
    pub g_bases: Vec<(Integer, bool)>
}

impl CL03CommitmentPublicKey {

    //verifier_pk -> N = issuer_pk.N
    //trusted_party_pk -> N = None
    pub fn generate<CS: CLCiphersuite>(N: Option<Integer>, n_attributes: Option<usize>) -> Self{
        let n = CS::SECPARAM; //SECPARAM
        let n_attributes = n_attributes.unwrap_or(1);
        let N = N.unwrap_or_else(|| {
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
            N
        });

        let h = random_qr(&N);

        let mut g_bases: Vec<(Integer, bool)> = Vec::new();

        for _i in 0..n_attributes {
            let mut f = random_number(N.clone());
            let mut g_i = Integer::from(h.pow_mod_ref(&f, &N).unwrap());

            loop {
                if ( (g_i > Integer::from(1)) && (Integer::from(g_i.gcd_ref(&N)) == Integer::from(1))) == false {
                    f = random_number(N.clone());
                    g_i = Integer::from(h.pow_mod_ref(&f, &N).unwrap());
                }
                else {
                    break;
                }
            }
            g_bases.push((g_i, true));
        }

        CL03CommitmentPublicKey{N: N, h: h, g_bases: g_bases}
    }
}

// #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
// pub struct CL03KeyPair {
//     private: CL03SecretKey,
//     public: CL03PublicKey
// }



// impl CL03KeyPair{

//     pub fn new(private: CL03SecretKey, public: CL03PublicKey) -> Self{
//         Self{private, public}
//     }

//     pub fn private(&self) -> &CL03SecretKey{
//         &self.private
//     }

//     pub fn public(&self) -> &CL03PublicKey{
//         &self.public
//     }

    // pub fn generate() -> Self {
    //     let n = 512; //SECPARAM
    //     let mut pprime = random_prime(n);
    //     let mut p = Integer::from(2) * pprime.clone() + Integer::from(1);
    //     loop{
    //         // println!("{} INT", p);
    //         // let digits = p.to_digits::<u8>(Order::MsfBe);
    //         // let bignum = BigUint::from_bytes_be(&digits);
    //         // println!("{} BIGNUM", bignum);
    //         if p.is_probably_prime(50) !=IsPrime::No {
    //             break;
    //         }
    //         pprime = random_prime(n);
    //         p = Integer::from(2) * pprime + Integer::from(1);
    //     }

    //     let mut qprime = random_prime(n);
    //     let mut q = Integer::from(2) * qprime.clone() + Integer::from(1);
    //     loop{
    //         // println!("{} INT", p);
    //         // let digits = p.to_digits::<u8>(Order::MsfBe);
    //         // let bignum = BigUint::from_bytes_be(&digits);
    //         // println!("{} BIGNUM", bignum);
    //         if p != q && q.is_probably_prime(100) !=IsPrime::No {
    //             break;
    //         }
    //         qprime = random_prime(n);
    //         q = Integer::from(2) * qprime + Integer::from(1);
    //     }

    //     let N = p.clone() * q.clone();
    
    //     let mut a_bases: Vec<Integer> = Vec::new();
    //     let a0 = random_qr(&N);

    //     a_bases.push(a0);

    //     let b = random_qr(&N);
    //     let c = random_qr(&N);

    //     let pk = CL03PublicKey::new(N, b, c, a_bases);
    //     let sk = CL03SecretKey::new(p, q);

    //     //let pair = CL03KeyPair::new(sk, pk);
    //     Self{public: pk, private: sk }
    //     // Self{public: PublicKey::new(PublicKeyData::CL03(pk)), private: PrivateKey::new(PrivateKeyData::CL03(sk)), p: PhantomData}

    // }
// }

