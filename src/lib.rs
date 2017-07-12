#![cfg_attr(not(feature = "std"),  no_std)]
#![cfg_attr(test, deny(warnings))]
#![deny(missing_docs)]
#![deny(dead_code)]
//! # parsip
//!
//! A push library for parsing SIP requests and responses.
//!

#[cfg(feature = "std")]
extern crate std as core;

#[macro_use]
extern crate nom;

mod sip;

pub use sip::*;
