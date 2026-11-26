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
