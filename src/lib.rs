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

