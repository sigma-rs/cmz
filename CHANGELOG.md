# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-10-10

### Added

- Initial release

## [0.2.0] - 2026-03-25

### Added

- Add `set_keypair` function to CMZ credentials.  This function sets
  both the private and public keys, without recomputing the public key
  from the private key.  Using this function saves computation when you
  have both keys at hand.
- The new `dump` feature enables the corresponding `dump` feature of the
  `sigma_compiler` crate.

### Changes

- Don't serialize an 8-byte length header in front of each Scalar and
  Point, which makes the generated proofs noticeably shorter.
- Depend on `sigma-compiler` version 0.2.0

### Fixes

- Remove nondeterministic order of generated statements in the call to
  the `sigma_compiler` macro.  We need the generated statements to be
  identical, not just equivalent (e.g., the same statements in a
  different order) because the order of the elements in the proof
  depends on the order of the statements.
- Don't use WnafBase multiplication at this time.  It's both not
  constant time, and also in some cases slower than the regular
  multiplication (at least with Ristretto).


[0.1.0]: https://git-crysp.uwaterloo.ca/SigmaProtocol/cmz/src/0.1.0
[0.2.0]: https://git-crysp.uwaterloo.ca/SigmaProtocol/cmz/src/0.2.0
