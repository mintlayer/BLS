// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): B. Marsh
#![deny(missing_debug_implementations)]
#![deny(unsafe_code)]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

/**
 * BLS implementation
 * 
 * WARNING THIS CODE HAS NOT BEEN AUDITED
 * 
 **/
extern crate bls12_381_plus;
extern crate ff;
extern crate group;
extern crate hkdf;
extern crate pairing;
extern crate serde;
extern crate sha2;
extern crate subtle;
extern crate zeroize;

mod signature;
pub use signature::*;
//TODO add some automated tests back in. The old tests still pass I just need to add them back :)

