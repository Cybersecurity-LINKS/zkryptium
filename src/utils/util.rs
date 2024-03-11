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



#[cfg(feature = "bbsplus")]
pub mod bbsplus_utils {
    use std::{any::{TypeId, Any}, borrow::Borrow};
    use ff::Field;
    use rand::{random, RngCore};
    use rand::rngs::OsRng;
    use bls12_381_plus::{Scalar, G1Projective, G2Projective};
    use elliptic_curve::{hash2curve::{ExpandMsg, Expander}, group::Curve};
    use crate::{bbsplus::generators::Generators, errors::Error, utils::message::BBSplusMessage};
    use crate::{bbsplus::ciphersuites::BbsCiphersuite, bbsplus::keys::BBSplusPublicKey};

    const NONCE_LENGTH: usize = 16;

    pub fn generate_nonce() -> Vec<u8> {
        let mut rng = OsRng::default();
        let mut nonce = vec![0; NONCE_LENGTH];
        rng.fill_bytes(&mut nonce);

        nonce
    }


    pub fn i2osp(x: usize, x_len: usize) -> Vec<u8> {
        let mut result = Vec::new();
    
        let mut x_copy = x;
    
        for _ in 0..x_len {
            result.push((x_copy % 256) as u8);
            x_copy /= 256;
        }
    
        result.reverse(); // Since the most significant byte is at the end
        result
    }
    

    // UPDATE
    /// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bbs-signatures-05#name-hash-to-scalar -> hashed_scalar = hash_to_scalar(msg_octets, dst)
    /// 
    /// # Description
    /// This operation describes how to hash an arbitrary octet string to a scalar values in the multiplicative group of integers mod r
    /// 
    /// # Inputs:
    /// * `msg_octets` (REQUIRED), an octet string. The message to be hashed.
    /// * `dst` (REQUIRED), an octet string representing a domain separation tag.
    /// 
    /// # Output:
    /// * a [`Scalar`].
    /// 
    pub fn hash_to_scalar_new<CS: BbsCiphersuite>(msg_octects: &[u8], dst: &[u8]) -> Result<Scalar, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        if dst.len() > 255 {
            return Err(Error::HashToScalarError)
        }
        let mut uniform_bytes = vec!(0u8; CS::EXPAND_LEN);
        let dsts = [dst];

        // uniform_bytes = expand_message(msg_octets, dst, expand_len)
        CS::Expander::expand_message(&[msg_octects], &dsts, CS::EXPAND_LEN).map_err(|_| Error::HashToScalarError)?
            .fill_bytes(&mut uniform_bytes);

        // OS2IP(uniform_bytes) mod r
        Ok(Scalar::from_okm(uniform_bytes.as_slice().try_into().map_err(|_| Error::HashToScalarError)?))

        

    }


    pub fn hash_to_scalar<C: BbsCiphersuite>(msg_octects: &[u8], dst: Option<&[u8]>) -> Scalar 
    where
        C::Expander: for<'a> ExpandMsg<'a>,
    {
        let binding = [C::ID, b"H2S_"].concat();
        let default_dst = binding.as_slice();
        let dst = dst.unwrap_or(default_dst);

        let mut counter: u8 = 0;
        let mut hashed_scalar = Scalar::from(0u32);

        let mut uniform_bytes = vec!(0u8; C::EXPAND_LEN);

        let mut msg_prime: Vec<u8>;

        while hashed_scalar == Scalar::from(0u32) {

            // msg_prime = [msg_octects, &[counter; 1][..], &[0u8, 0u8, 0u8, 1u8][..]].concat();
            msg_prime = [msg_octects, &[counter; 1][..]].concat(); //from UPDATED STANDARD
            C::Expander::expand_message(&[msg_prime.as_slice()], &[dst], C::EXPAND_LEN).unwrap().fill_bytes(&mut uniform_bytes);
            hashed_scalar = Scalar::from_okm(uniform_bytes.as_slice().try_into().unwrap());

            counter = counter + 1;
        }

        hashed_scalar
    }


    pub fn hash_to_scalar_old<C: BbsCiphersuite>(msg_octects: &[u8], count: usize, dst: Option<&[u8]>) -> Vec<Scalar> 
    where
        C::Expander: for<'a> ExpandMsg<'a>,
    {
        let binding = [C::ID, "H2S_".as_bytes()].concat();
        let default_dst = binding.as_slice();
        let dst = dst.unwrap_or(default_dst);

        let mut t: u8 = 0;
        let len_in_bytes = count * C::EXPAND_LEN;
        // let mut hashed_scalar = Scalar::from(0);

        let mut uniform_bytes = vec!(0u8; len_in_bytes);

        let mut msg_prime: Vec<u8>;
        let mut scalars: Vec<Scalar> = Vec::new();

        let mut repeat = true;
        while repeat {
            repeat = false;
            msg_prime = [msg_octects, &[t; 1][..], &[0u8, 0u8, 0u8, count.try_into().unwrap()][..]].concat();
            C::Expander::expand_message(&[msg_prime.as_slice()], &[dst], len_in_bytes).unwrap().fill_bytes(&mut uniform_bytes);
            for i in 0..count {
                let tv = &uniform_bytes[i*C::EXPAND_LEN..(i+1)*C::EXPAND_LEN];
                let scalar_i = Scalar::from_okm(tv.try_into().unwrap());
                if scalar_i == Scalar::from(0u32) {
                    t = t + 1;
                    repeat = true;
                    break;
                }
                else {
                    scalars.push(scalar_i);
                }
            }
        }
        scalars
    }


    pub fn subgroup_check_g1(p: G1Projective) -> bool {
        if p.is_on_curve().into() /*&& p.is_identity().into()*/ {
            true
        }
        else {
            false
        }
    }


    pub(crate) fn calculate_domain<CS: BbsCiphersuite>(pk: &BBSplusPublicKey, q1: G1Projective, q2: G1Projective, h_points: &[G1Projective], header: Option<&[u8]>) -> Scalar
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let header = header.unwrap_or(b"");

        let L = h_points.len();

        //da non mettere perchè in rust non potrà mai superare usize::MAX che è molto minore di 2^64 (questo perchè è type based, in python ci puoi mettere invece quello che vuoi e non ci sono queste limitazioni)
        // if header.len() > 2usize.pow(64)-1 || L > 2usize.pow(64)-1 {
        //     panic!("len(header) > 2^64 - 1 or L > 2^64 - 1");
        // } 

        let mut dom_octs: Vec<u8> = Vec::new();
        dom_octs.extend_from_slice(&L.to_be_bytes());
        dom_octs.extend_from_slice(&q1.to_affine().to_compressed());
        dom_octs.extend_from_slice(&q2.to_affine().to_compressed());

        h_points.iter().map(|&p| p.to_affine().to_compressed()).for_each(|a| dom_octs.extend_from_slice(&a));

        dom_octs.extend_from_slice(CS::ID);

        let mut dom_input: Vec<u8> = Vec::new();
        dom_input.extend_from_slice(&pk.to_bytes());
        dom_input.extend_from_slice(&dom_octs);

        let header_i2osp: [u8; 8] = (header.len() as u64).to_be_bytes();

        dom_input.extend_from_slice(&header_i2osp);
        dom_input.extend_from_slice(header);

        // let domain = hash_to_scalar::<CS>(&dom_input, None);
        let domain = hash_to_scalar_old::<CS>(&dom_input, 1, None)[0];
        domain
    }


    //UPDATED
    pub(crate) fn calculate_domain_new<CS: BbsCiphersuite>(pk: &BBSplusPublicKey, generators: &Generators, header: Option<&[u8]>, api_id: Option<&[u8]>) -> Result<Scalar, Error>
    where
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let header = header.unwrap_or(b"");

        let L = generators.message_generators.len();

        let api_id = api_id.unwrap_or(b"");

        let domain_dst = [api_id, CS::H2S].concat();

        let mut dom_octs: Vec<u8> = Vec::new();
        dom_octs.extend_from_slice(&L.to_be_bytes());
        dom_octs.extend_from_slice(&generators.q1.to_affine().to_compressed());

        generators.message_generators.iter().map(|&p| p.to_affine().to_compressed()).for_each(|a| dom_octs.extend_from_slice(&a));

        dom_octs.extend_from_slice(CS::API_ID);

        let mut dom_input: Vec<u8> = Vec::new();
        dom_input.extend_from_slice(&pk.to_bytes());
        dom_input.extend_from_slice(&dom_octs);

        let header_i2osp = i2osp(header.len(), 8);

        dom_input.extend_from_slice(&header_i2osp);
        dom_input.extend_from_slice(header);

        hash_to_scalar_new::<CS>(&dom_input, &domain_dst)
    }

    pub trait ScalarExt {
        fn to_bytes_be(&self) -> [u8; 32];
        fn from_bytes_be(bytes: &[u8; 32]) -> Result<Scalar, Error>;
    }

    impl ScalarExt for Scalar {
        fn to_bytes_be(&self) -> [u8; 32] {
            let bytes = self.to_be_bytes();
            // bytes.reverse();
            bytes
        }

        fn from_bytes_be(bytes: &[u8; 32]) -> Result<Self, Error> {
            let mut bytes_le = [0u8; 32];
            bytes_le.copy_from_slice(bytes);
            // bytes_le.reverse();
            let s = Scalar::from_be_bytes(&bytes_le);

            if s.is_none().into() {
                return Err(Error::InvalidProofOfKnowledgeSignature);
            }

            Ok(s.unwrap())
        }
    }


    pub fn serialize<T>(array: &[T]) -> Vec<u8>
    where
        T: Any,
    {
        let mut result:Vec<u8> = Vec::new();
        if array.len() == 0 {
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
            println!("Unknown struct type");
        }

        result
    }


    pub fn get_messages(messages: &[BBSplusMessage], indexes: &[usize]) -> Vec<BBSplusMessage> {
        let mut out: Vec<BBSplusMessage> = Vec::new();
        for &i in indexes {
            out.push(messages[i]);
        }

        out

    }

    pub fn get_messages_vec(messages: &[Vec<u8>], indexes: &[usize]) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = Vec::new();
        for &i in indexes {
            out.push(messages[i].clone());
        }

        out

    }

    pub(crate) fn get_random() -> Scalar {
        let rng = rand::thread_rng();
        Scalar::random(rng)
    }

    #[cfg(not(test))]
    pub fn calculate_random_scalars(count: usize) -> Vec<Scalar> 
    {

        let mut random_scalars: Vec<Scalar> =  Vec::new();

        for _i in 0..count {
            random_scalars.push(get_random());
        }

        random_scalars
    }



    #[cfg(test)]
    pub fn seeded_random_scalars<CS>(count: usize, seed: Option<&[u8]>, dst: Option<&[u8]>) -> Vec<Scalar> 
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {
        let binding = hex::decode("332e313431353932363533353839373933323338343632363433333833323739").unwrap();
        let seed = seed.unwrap_or(&binding);
        let binding2 = [CS::API_ID, CS::MOCKED_SCALAR].concat();
        let dst = dst.unwrap_or(&binding2); 

        let out_len = CS::EXPAND_LEN * count;
        let mut v = vec![0u8; out_len];

        CS::Expander::expand_message(&[&seed], &[&dst], out_len).unwrap().fill_bytes(&mut v);

        let mut scalars: Vec<Scalar> = Vec::new();

        for i in 1..count+1 {
            let start_idx = (i-1) * CS::EXPAND_LEN;
            let end_idx = i * CS::EXPAND_LEN;
            let okm= &v[start_idx..end_idx].try_into().unwrap();
            let scalar = Scalar::from_okm(okm);
            scalars.push(scalar);
        }

        scalars
    }


    // UPDATE
    /// https://datatracker.ietf.org/doc/html/draft-kalos-bbs-blind-signatures-00#name-blind-challenge-calculation -> challenge = calculate_blind_challenge(C, Cbar, generators, api_id)
    /// 
    /// # Description
    /// Utility function to generate a challenge
    /// 
    /// # Inputs:
    /// * `C` (REQUIRED), a point of G1.
    /// * `Cbar` (REQUIRED), a point of G1.
    /// * `generators` (REQUIRED), an array of points from G1, of length at
    /// least 1.
    /// * `api_id` (OPTIONAL), octet string. If not supplied it defaults to the
    /// empty octet string ("").
    /// 
    /// # Output:
    /// * a [`Scalar`].
    /// 
    pub fn calculate_blind_challenge<CS>(C: G1Projective, Cbar: G1Projective, generators: &[G1Projective], api_id: Option<&[u8]>) -> Result<Scalar, Error> 
    where
        CS: BbsCiphersuite,
        CS::Expander: for<'a> ExpandMsg<'a>,
    {

        if generators.len() == 0 {
            return Err(Error::NotEnoughGenerators)
        }

        let M = generators.len()-1;
        let api_id = api_id.unwrap_or(b"");
        let blind_challenge_dst = [api_id, CS::H2S].concat();

        let mut c_arr: Vec<u8> = Vec::new();
        c_arr.extend_from_slice(&C.to_affine().to_compressed());
        c_arr.extend_from_slice(&Cbar.to_affine().to_compressed());
        c_arr.extend_from_slice(&i2osp(M, 8));
        generators.iter().for_each(|&i| c_arr.extend_from_slice(&i.to_affine().to_compressed()));

        hash_to_scalar_new::<CS>(&c_arr, &blind_challenge_dst)
    }

}




#[cfg(feature = "cl03")]
pub mod cl03_utils {
    use rug::{Integer, integer::Order};

    //b*x = a mod m -> return x
    pub fn divm(a: &Integer, b: &Integer, m: &Integer) -> Integer{
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

        
    pub trait IntegerExt{
        fn to_bytes_be(&self, len: usize) -> Vec<u8>;
        // fn from_bytes_be(bytes: &[u8], len: usize) -> Self;
    }

    impl IntegerExt for Integer {
        fn to_bytes_be(&self, len: usize) -> Vec<u8> {
            let mut bytes = vec!(0u8; len);
            self.write_digits(&mut bytes, Order::MsfBe);
            bytes
        }

        // fn from_bytes_be(bytes: &[u8], len: usize) -> Self {
        //     let i = Integer::from_digits(&bytes[0usize .. len], Order::MsfBe);
        //     i
        // }
    }


}



pub(crate) fn get_remaining_indexes(length: usize, indexes: &[usize]) -> Vec<usize>{
    let mut remaining: Vec<usize> = Vec::new();

    for i in 0..length {
        if indexes.contains(&i) == false {
            remaining.push(i);
        }
    }

    remaining
}

