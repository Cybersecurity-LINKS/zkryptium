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

use super::CL03SecretKey;
use rug::Integer;

// p and q must not leak through {:?}.
#[test]
fn secret_key_debug_is_redacted() {
    let sk = CL03SecretKey::new(Integer::from(1_000_003), Integer::from(1_000_033));
    let debug = format!("{:?}", sk);
    assert_eq!(debug, "CL03SecretKey(<redacted>)");
    assert!(!debug.contains("1000003"));
}
