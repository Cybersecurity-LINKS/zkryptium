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

//! Helpers shared by the BBS+ unit tests to read the JSON test vectors in `fixture_data/`.

use serde_json::Value;

#[cfg(feature = "bbsplus_blind")]
use super::{commitment::Message, proof::Disclosure};

/// Reads and parses the JSON fixture at `path`.
pub(crate) fn read_fixture(path: &str) -> Value {
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Unable to read fixture {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("Unable to parse fixture {path}: {e}"))
}

/// Decodes the hex string `v`, panicking with a useful message if it is missing or malformed.
pub(crate) fn hex_value(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("fixture value is not a string")).expect("invalid hex in fixture")
}

/// Decodes the hex value under `key` from every fixture in `dir` whose `result.valid` is `true`.
pub(crate) fn valid_fixture_bytes(dir: &str, key: &str) -> Vec<Vec<u8>> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .expect("Unable to read fixture directory")
        .map(|e| e.expect("Unable to read fixture entry").path())
        .collect();
    paths.sort();

    let values: Vec<Vec<u8>> = paths
        .iter()
        .filter_map(|path| {
            let json = read_fixture(path.to_str().expect("non UTF-8 fixture path"));
            if json["result"]["valid"].as_bool() == Some(true) {
                Some(hex_value(&json[key]))
            } else {
                None
            }
        })
        .collect();

    assert!(!values.is_empty(), "no valid fixtures found in {dir}");
    values
}

/// Parses a Blind BBS message in the `[flag, hex value]` form of the draft 05 test vectors.
#[cfg(feature = "bbsplus_blind")]
pub(crate) fn parse_message(v: &Value) -> Message {
    let pair = v.as_array().expect("message: [flag, hex]");
    let flag = pair[0].as_str().expect("message: flag is not a string").to_owned();
    Message::try_from((flag, hex_value(&pair[1]))).expect("message: unknown flag")
}

/// Parses a list of messages (see [`parse_message`]); a missing field is the empty list.
#[cfg(feature = "bbsplus_blind")]
pub(crate) fn parse_messages(v: &Value) -> Vec<Message> {
    v.as_array().map(|a| a.iter().map(parse_message).collect()).unwrap_or_default()
}

/// Parses a list of disclosure values (`"DISCLOSE"`, `"HIDE"`, `"COMMIT"`); a missing field is the
/// empty list.
#[cfg(feature = "bbsplus_blind")]
pub(crate) fn parse_disclosures(v: &Value) -> Vec<Disclosure> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|d| Disclosure::try_from(d.as_str().expect("disclosure is not a string")).unwrap())
                .collect()
        })
        .unwrap_or_default()
}
