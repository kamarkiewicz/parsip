#![cfg_attr(not(feature = "std"),  no_std)]
#![cfg_attr(test, deny(warnings))]
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

pub use sip::*;
