// Copyright 2026 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::cl03::ciphersuites::{CLCiphersuite};
use crate::schemes::algorithms::{CL03_CL1024_SHA256, CL03_CL2048_SHA256, CL03_CL3072_SHA256};
use crate::{
    cl03::bases::Bases,
    keys::pair::KeyPair,
    schemes::algorithms::{Ciphersuite, Scheme, CL03},
    schemes::generics::Signature,
    utils::message::cl03_message::CL03Message,
};
use digest::Digest;

//Signature (sign) - CL1024-SHA256
#[test]
fn signature_cl1024_sha256() {
    signature::<CL03_CL1024_SHA256>();
}

#[test]
fn signature_cl2048_sha256() {
    signature::<CL03_CL2048_SHA256>();
}

#[test]
fn signature_cl3072_sha256() {
    signature::<CL03_CL3072_SHA256>();
}

#[test]
fn keypair_cl1024_sha256() {
    keypair::<CL03_CL1024_SHA256>();
}

#[test]
fn keypair_cl2048_sha256() {
    keypair::<CL03_CL2048_SHA256>();
}

#[test]
fn keypair_cl3072_sha256() {
    keypair::<CL03_CL3072_SHA256>();
}

fn keypair<S: Scheme>()
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
{
     KeyPair::<CL03<S::Ciphersuite>>::generate();
}

fn signature<S: Scheme>()
where
    S::Ciphersuite: CLCiphersuite,
    <S::Ciphersuite as Ciphersuite>::HashAlg: Digest,
{
    const msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    const wrong_msg: &str = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f03";

    let cl03_keypair = KeyPair::<CL03<S::Ciphersuite>>::generate();
    let a_bases = Bases::generate(cl03_keypair.public_key(), 1);

    let message = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
        &hex::decode(msg).unwrap(),
    );

    let wrong_message = CL03Message::map_message_to_integer_as_hash::<S::Ciphersuite>(
        &hex::decode(wrong_msg).unwrap(),
    );

    let signature = Signature::<CL03<S::Ciphersuite>>::sign(
        cl03_keypair.public_key(),
        cl03_keypair.private_key(),
        &a_bases,
        &message,
    )
    .unwrap();

    let valid = signature.verify(cl03_keypair.public_key(), &a_bases, &message);

    assert!(valid, "Error! Signature should be VALID");

    let valid = signature.verify(cl03_keypair.public_key(), &a_bases, &wrong_message);

    assert!(!valid, "Error! Signature should be INVALID");
}
