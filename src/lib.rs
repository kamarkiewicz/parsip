#![cfg_attr(not(feature = "std"),  no_std)]
// FIXME: unnecessary parentheses around function argument caused by do_parse!
// #![cfg_attr(test, deny(warnings))]
#![deny(missing_docs)]
#![deny(dead_code)]
//! # parsip
//!
//! A push library for parsing SIP requests and responses.
//!

#[macro_use]
extern crate nom;

#[cfg(not(feature = "std"))]
mod std {
    pub use core::*;
}

mod sip;
mod lookup;

pub use sip::*;
