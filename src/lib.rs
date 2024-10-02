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

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused)]
#[macro_use]
extern crate alloc;

pub mod errors;
pub mod keys;
pub mod schemes;
pub mod utils;

#[cfg(feature = "min_bbs")]
pub mod bbsplus;
#[cfg(feature = "cl03")]
pub mod cl03;
