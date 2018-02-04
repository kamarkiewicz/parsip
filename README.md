# parsip

[![Build Status](https://travis-ci.org/kamarkiewicz/parsip.svg?branch=master)](https://travis-ci.org/kamarkiewicz/parsip)
[![codecov](https://codecov.io/gh/kamarkiewicz/parsip/branch/master/graph/badge.svg)](https://codecov.io/gh/kamarkiewicz/parsip)
[![crates.io](https://img.shields.io/crates/v/parsip.svg?maxAge=2592000)](https://crates.io/crates/parsip)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A push parser for the SIP protocol.
Uses [nom for parser combinators](https://github.com/Geal/nom/) under the hood.

Works with `no_std`, simply disable the `std` Cargo feature.
Only on nightly channel for now, because `nom` requires `feature(alloc)`.

### Compliant with

  - [RFC 3261](https://tools.ietf.org/html/rfc3261) - SIP basics
  - [RFC 4475](https://tools.ietf.org/html/rfc4475) - stress tests
