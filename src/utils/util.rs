// Copyright 2023 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloc::vec::Vec;

#[cfg(any(feature = "min_bbs"))]
pub mod bbsplus_utils {
    use alloc::{borrow::ToOwned, vec::Vec, string::String};
    use core::any::{Any, TypeId};
    use crate::{
        errors::Error,
        bbsplus::ciphersuites::BbsCiphersuite,
        bbsplus::keys::BBSplusPublicKey,
        utils::message::bbsplus_message::BBSplusMessage,
    };
    use bls12_381_plus::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
    use elliptic_curve::{
        group::Curve,
        hash2curve::{ExpandMsg, Expander},
    };
    use ff::Field;
    use rand::{thread_rng, RngCore};

    pub(crate) fn parse_g2_projective_compressed(slice: &[u8]) -> Result<G2Projective, Error> {
        let point = G2Affine::from_compressed(
            &<[u8; G2Affine::COMPRESSED_BYTES]>::try_from(slice)
                .map_err(|_| Error::DeserializationError("Invalid G2 point".to_owned()))?,
        );
        if point.is_none().into() {
            return Err(Error::DeserializationError("Invalid G2 point".to_owned()));
        }
        Ok(point.map(G2Projective::from).unwrap())
    }

    pub(crate) fn parse_g2_projective_uncompressed(slice: &[u8]) -> Result<G2Projective, Error> {
        let point = G2Affine::from_uncompressed(
            &<[u8; G2Affine::UNCOMPRESSED_BYTES]>::try_from(slice)
                .map_err(|_| Error::DeserializationError("Invalid G2 point".to_owned()))?,
        );
        if point.is_none().into() {
            return Err(Error::DeserializationError("Invalid G2 point".to_owned()));
        }
        Ok(point.map(G2Projective::from).unwrap())
    }

    pub(crate) fn parse_g1_projective(slice: &[u8]) -> Result<G1Projective, Error> {
        let point = G1Affine::from_compressed(
            &<[u8; G1Affine::COMPRESSED_BYTES]>::try_from(slice)
                .map_err(|_| Error::DeserializationError("Invalid G1 point".to_owned()))?,
        );
        if point.is_none().into() {
            return Err(Error::DeserializationError("Invalid G1 point".to_owned()));
        }
        Ok(point.map(G1Projective::from).unwrap())
    }

    /// # Description
    /// Generate a random secret of `n` bytes
    /// # Input
    /// * `n` (REQUIRED), number of bytes
    ///
    /// # Output
    /// * Vec<u8>, a secret
    pub fn generate_random_secret(n: usize) -> Vec<u8> {
        let mut rng = thread_rng();
        let mut secret = vec![0; n]; // Initialize a vector of length n with zeros
        rng.fill_bytes(&mut secret); // Fill the vector with random bytes
        secret
    }

    pub fn i2osp<const N: usize>(x: usize) -> [u8; N] {
        const SYS_LEN: usize = (usize::BITS / 8) as usize;
        assert!(N >= SYS_LEN || x >> (8 * N) == 0, "i2osp overflow");
        let be_bytes = x.to_be_bytes();
        let mut out = [0; N];

        use core::cmp::Ordering;
        match N.cmp(&SYS_LEN) {
            Ordering::Equal => out.copy_from_slice(&be_bytes),
            Ordering::Greater => out[N - SYS_LEN..].copy_from_slice(&x.to_be_bytes()),
            Ordering::Less => out.copy_from_slice(&be_bytes[SYS_LEN - N..]),
        }
        out
    }

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-hash-to-scalar
    ///
    /// # Description
    /// This operation describes how to hash an arbitrary octet string to a scalar values in the multiplicative group of integers mod r
    ///
    /// # Inputs:
    /// * `msg_octets` (REQUIRED), an octet string. The message to be hashed.
    /// * `dst` (REQUIRED), an octet string representing a domain separation tag.
    ///
    /// # Output:
    /// * a [`Scalar`] or [`Error`]. or [`Error`]..
    ///
    pub fn hash_to_scalar<CS: BbsCiphersuite>(
        msg_octects: &[u8],
        dst: &[u8],
    ) -> Result<Scalar, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        if dst.len() > 255 {
            return Err(Error::HashToScalarError);
        }
        let mut uniform_bytes = vec![0u8; CS::EXPAND_LEN];
        let dsts = [dst];

        // uniform_bytes = expand_message(msg_octets, dst, expand_len)
        CS::Expander::expand_message(&[msg_octects], &dsts, CS::EXPAND_LEN)
            .map_err(|_| Error::HashToScalarError)?
            .fill_bytes(&mut uniform_bytes);

        // OS2IP(uniform_bytes) mod r
        Ok(Scalar::from_okm(
            uniform_bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::HashToScalarError)?,
        ))
    }

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-domain-calculation
    ///
    /// # Description
    /// This operation calculates the domain value, a scalar representing the distillation of all essential contextual information for a signature. The same domain value must be calculated by all parties (the Signer, the Prover and the Verifier) for both the signature and proofs to be validated.
    ///
    /// # Inputs:
    ///
    /// * `pk` (REQUIRED), an octet string, representing the public key of theSigner.
    /// * `Q1` (REQUIRED), point of G1 (the first point returned from create_generators).
    /// * `H_Points` (REQUIRED), array of points of G1.
    /// * `header` (OPTIONAL), an octet string. If not supplied, it must default to the empty octet string ("").
    /// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string ("").
    ///
    /// # Output:
    /// * a [`Scalar`] or [`Error`]..
    ///
    pub(crate) fn calculate_domain<CS: BbsCiphersuite>(
        pk: &BBSplusPublicKey,
        Q1: G1Projective,
        H_points: &[G1Projective],
        header: Option<&[u8]>,
        api_id: Option<&[u8]>,
    ) -> Result<Scalar, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let header = header.unwrap_or(b"");

        // 1. L = length(H_Points)
        // 2. (H_1, ..., H_L) = H_Points
        let L = H_points.len();

        let api_id = api_id.unwrap_or(b"");

        let domain_dst = [api_id, CS::H2S].concat();

        let mut dom_octs: Vec<u8> = Vec::new();
        dom_octs.extend_from_slice(&i2osp::<8>(L));
        dom_octs.extend_from_slice(&Q1.to_affine().to_compressed());

        H_points
            .iter()
            .map(|&p| p.to_affine().to_compressed())
            .for_each(|a| dom_octs.extend_from_slice(&a));

        dom_octs.extend_from_slice(api_id);

        let mut dom_input: Vec<u8> = Vec::new();
        dom_input.extend_from_slice(&pk.to_bytes());
        dom_input.extend_from_slice(&dom_octs);

        dom_input.extend_from_slice(&i2osp::<8>(header.len()));
        dom_input.extend_from_slice(header);

        hash_to_scalar::<CS>(&dom_input, &domain_dst)
    }

    pub trait ScalarExt {
        fn to_bytes_be(&self) -> [u8; 32];
        fn from_bytes_be(bytes: &[u8]) -> Result<Scalar, Error>;
        fn encode(&self) -> String;
    }

    impl ScalarExt for Scalar {
        fn to_bytes_be(&self) -> [u8; 32] {
            let bytes = self.to_be_bytes();
            bytes
        }

        fn from_bytes_be(bytes: &[u8]) -> Result<Self, Error> {
            let be_bytes = <[u8; Scalar::BYTES]>::try_from(bytes)
                .map_err(|_| Error::DeserializationError("Not a valid Scalar".to_owned()))?;
            let s = Scalar::from_be_bytes(&be_bytes);

            if s.is_none().into() {
                return Err(Error::DeserializationError("Not a valid Scalar".to_owned()));
            }

            Ok(s.unwrap())
        }

        fn encode(&self) -> String {
            hex::encode(self.to_bytes_be())
        }
    }

    pub fn serialize<T>(array: &[T]) -> Vec<u8>
    where
        T: Any,
    {
        let mut result: Vec<u8> = Vec::new();
        if array.len() == 0 {
            #[cfg(feature = "std")]
            println!("Empty array");
            return result;
        }

        let first_type = TypeId::of::<T>();

        if first_type == TypeId::of::<Scalar>() {
            // Perform actions specific to Scalar struct
            for element in array.iter() {
                let element_any = element as &dyn Any;
                if let Some(scalar) = element_any.downcast_ref::<Scalar>() {
                    // Process Scalar element
                    // ...
                    result.extend_from_slice(&scalar.to_bytes_be());
                }
            }
        } else if first_type == TypeId::of::<G1Projective>() {
            // Perform actions specific to Projective struct
            for element in array.iter() {
                let element_any = element as &dyn Any;
                if let Some(g1) = element_any.downcast_ref::<G1Projective>() {
                    // Process Scalar element
                    // ...
                    result.extend_from_slice(&g1.to_affine().to_compressed());
                }
            }
        } else if first_type == TypeId::of::<G2Projective>() {
            // Perform actions specific to Projective struct
            for element in array.iter() {
                let element_any = element as &dyn Any;
                if let Some(g2) = element_any.downcast_ref::<G2Projective>() {
                    // Process Scalar element
                    // ...
                    result.extend_from_slice(&g2.to_affine().to_compressed());
                }
            }
        } else {
            #[cfg(feature = "std")]
            println!("Unknown struct type");
        }

        result
    }

    pub fn get_messages(messages: &[BBSplusMessage], indexes: &[usize]) -> Vec<BBSplusMessage> {
        indexes.into_iter().map(|&i| messages[i]).collect()
    }

    pub fn get_messages_vec(messages: &[Vec<u8>], indexes: &[usize]) -> Vec<Vec<u8>> {
        indexes
            .into_iter()
            .map(|&i| messages[i].clone())
            .collect()
    }

    pub(crate) fn get_random() -> Scalar {
        let rng = rand::thread_rng();
        Scalar::random(rng)
    }

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-random-scalars
    ///
    /// # Description
    /// This operation returns the requested number of pseudo-random scalars, using the `get_random` function
    ///
    /// # Inputs:
    ///
    /// * `count` (REQUIRED), usize. The number of scalars to return.
    ///
    /// # Output:
    /// * a [`Vec<Scalar>`].
    ///
    #[cfg(not(test))]
    pub fn calculate_random_scalars(count: usize) -> Vec<Scalar> {
        let mut random_scalars: Vec<Scalar> = Vec::new();

        for _i in 0..count {
            random_scalars.push(get_random());
        }

        random_scalars
    }

    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-06#name-mocked-random-scalars
    ///
    /// # Description
    /// The seeded_random_scalars will deterministically calculate count random-looking scalars from a single SEED, given a domain separation tag (DST).
    ///
    /// # Inputs:
    ///
    /// * `count` (REQUIRED), usize. The number of scalars to return.
    /// * `seed` (REQUIRED), an octet string. The random seed from which to generate the scalars.
    /// * `dst` (REQUIRED), octet string representing a domain separation tag.
    ///
    /// # Output:
    /// * a [`Vec<Scalar>`].
    ///
    #[cfg(test)]
    pub fn seeded_random_scalars<CS>(count: usize, seed: &[u8], dst: &[u8]) -> Vec<Scalar>
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        // let binding = hex::decode("332e313431353932363533353839373933323338343632363433333833323739").unwrap();
        // let seed = seed.unwrap_or(&binding);
        // let binding2 = [CS::API_ID, CS::MOCKED_SCALAR].concat();
        // let dst = dst.unwrap_or(&binding2);

        let out_len = CS::EXPAND_LEN * count;
        let mut v = vec![0u8; out_len];

        CS::Expander::expand_message(&[&seed], &[&dst], out_len)
            .unwrap()
            .fill_bytes(&mut v);

        let mut scalars: Vec<Scalar> = Vec::new();

        for i in 1..count + 1 {
            let start_idx = (i - 1) * CS::EXPAND_LEN;
            let end_idx = i * CS::EXPAND_LEN;
            let okm = &v[start_idx..end_idx].try_into().unwrap();
            let scalar = Scalar::from_okm(okm);
            scalars.push(scalar);
        }

        scalars
    }

    /// https://datatracker.ietf.org/doc/html/draft-kalos-bbs-blind-signatures-01#name-blind-challenge-calculation
    ///
    /// # Description
    /// Utility function to generate a challenge
    ///
    /// # Inputs:
    /// * `C` (REQUIRED), a point of G1.
    /// * `Cbar` (REQUIRED), a point of G1.
    /// * `generators` (REQUIRED), an array of points from G1, of length at least 1.
    /// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the empty octet string ("").
    ///
    /// # Output:
    /// * a [`Scalar`] or [`Error`].
    ///
    pub fn calculate_blind_challenge<CS>(
        C: G1Projective,
        Cbar: G1Projective,
        generators: &[G1Projective],
        api_id: Option<&[u8]>,
    ) -> Result<Scalar, Error>
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        if generators.len() == 0 {
            return Err(Error::NotEnoughGenerators);
        }

        let M = generators.len() - 1;
        let api_id = api_id.unwrap_or(b"");
        let blind_challenge_dst = [api_id, CS::H2S].concat();

        let mut c_arr: Vec<u8> = Vec::new();
        c_arr.extend_from_slice(&i2osp::<8>(M));
        generators
            .iter()
            .for_each(|&i| c_arr.extend_from_slice(&i.to_affine().to_compressed()));
        c_arr.extend_from_slice(&C.to_affine().to_compressed());
        c_arr.extend_from_slice(&Cbar.to_affine().to_compressed());

        hash_to_scalar::<CS>(&c_arr, &blind_challenge_dst)
    }

    #[cfg(test)]
    mod tests {

        use crate::bbsplus::ciphersuites::BbsCiphersuite;
        use crate::schemes::algorithms::Scheme;
        use crate::schemes::algorithms::{BbsBls12381Sha256, BbsBls12381Shake256};
        use crate::utils::util::bbsplus_utils::{hash_to_scalar, ScalarExt};
        use elliptic_curve::hash2curve::ExpandMsg;
        use std::fs;

        //h2s - SHA256
        #[test]
        fn h2s_sha256_1() {
            h2s::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "h2s.json");
        }
        #[test]
        fn h2s_sha256_2() {
            h2s::<BbsBls12381Sha256>("./fixture_data/bls12-381-sha-256/", "h2s.json");
        }

        //h2s - SHAKE256
        #[test]
        fn h2s_shake256_1() {
            h2s::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "h2s.json");
        }
        #[test]
        fn h2s_shake256_2() {
            h2s::<BbsBls12381Shake256>("./fixture_data/bls12-381-shake-256/", "h2s.json");
        }

        fn h2s<S: Scheme>(pathname: &str, filename: &str)
        where
            S::Ciphersuite: BbsCiphersuite,
            <S::Ciphersuite as BbsCiphersuite>::Expander: for<'a> ExpandMsg<'a>,
        {
            let data =
                fs::read_to_string([pathname, filename].concat()).expect("Unable to read file");
            let res: serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
            println!("{}\n", res["caseName"]);

            let msg_hex = res["message"].as_str().unwrap();
            let dst_hex = res["dst"].as_str().unwrap();
            let scalar_hex_expected = res["scalar"].as_str().unwrap();

            let msg = hex::decode(msg_hex).unwrap();
            let dst = hex::decode(dst_hex).unwrap();

            let scalar = hash_to_scalar::<S::Ciphersuite>(&msg, &dst).unwrap();

            let mut result = true;

            let scalar_hex = hex::encode(scalar.to_bytes_be());

            if scalar_hex != scalar_hex_expected {
                result = false;
                eprintln!("{}", result);

                eprintln!(" Expected scalar: {}", scalar_hex_expected);
                eprintln!(" Computed scalar: {}", scalar_hex);
            }

            assert!(result, "Failed");
        }
    }
}

#[cfg(feature = "cl03")]
pub mod cl03_utils {
    use alloc::vec::Vec;
    use rug::{integer::Order, Integer};

    //b*x = a mod m -> return x
    pub fn divm(a: &Integer, b: &Integer, m: &Integer) -> Integer {
        let mut num = a.clone();
        let den;
        let mut module = m.clone();
        let r: Integer;
        let mut result = b.invert_ref(&m);
        let mut ok = result.is_none();
        if ok {
            let mut gcd = Integer::from(a.gcd_ref(&b));
            gcd.gcd_mut(&m);
            num = Integer::from(a.div_exact_ref(&gcd));
            den = Integer::from(b.div_exact_ref(&gcd));
            module = Integer::from(m.div_exact_ref(&gcd));
            result = den.invert_ref(&module);
            ok = result.is_none();
        }

        if !ok {
            r = Integer::from(result.unwrap());
            let z = (r * num) % module;
            z
        } else {
            panic!("No solution");
        }
    }

    pub trait IntegerExt {
        fn to_bytes_be(&self, len: usize) -> Vec<u8>;
        // fn from_bytes_be(bytes: &[u8], len: usize) -> Self;
    }

    impl IntegerExt for Integer {
        fn to_bytes_be(&self, len: usize) -> Vec<u8> {
            let mut bytes = vec![0u8; len];
            self.write_digits(&mut bytes, Order::MsfBe);
            bytes
        }

        // fn from_bytes_be(bytes: &[u8], len: usize) -> Self {
        //     let i = Integer::from_digits(&bytes[0usize .. len], Order::MsfBe);
        //     i
        // }
    }
}

pub(crate) fn get_remaining_indexes(length: usize, indexes: &[usize]) -> Vec<usize> {
    let mut remaining: Vec<usize> = Vec::new();

    for i in 0..length {
        if indexes.contains(&i) == false {
            remaining.push(i);
        }
    }

    remaining
}

#[cfg(test)]
mod tests {
    use super::bbsplus_utils::i2osp;

    #[test]
    fn test_i2osp() {
        assert_eq!([0, 0, 0, 0, 1, 2, 3, 4], i2osp::<8>(0x1020304));
        assert_eq!([0xf0, 0x0f], i2osp::<2>(0xf00f));
        assert_eq!([0, 0, 0, 0, 0, 0, 0x12, 0x34], i2osp::<8>(0x1234));
        assert_eq!([0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78], i2osp::<8>(0x12345678));
        assert_eq!([0, 0, 0x12, 0x34, 0x56, 0x78], i2osp::<6>(0x12345678));
        assert_eq!([0, 0x12, 0x34, 0x56, 0x78], i2osp::<5>(0x12345678));
        assert_eq!([0x12, 0x34, 0x56, 0x78], i2osp::<4>(0x12345678));
        assert_eq!(
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78],
            i2osp::<13>(0x12345678)
        );
    }

    #[test]
    #[should_panic(expected = "i2osp overflow")]
    fn test_i2osp_over() {
        let _x = i2osp::<3>(0x12345678);
    }
}
