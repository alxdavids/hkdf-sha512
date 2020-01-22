//! The hkdf module provides access to the functionality provoided HKDF as
//! specified in [RFC5869](https://tools.ietf.org/html/rfc5869)
//!
//! A wrapper around the rust-crypto implementation of HKDF
//! [RFC5869](https://tools.ietf.org/html/rfc5869) locked to using SHA512 as the
//! underlying hash function. The abstraction is necessary so that we can
//! provide multiple sized output buffers, where the HKDF instance.
//!
//! TODO: Rewrite to use the ring implementation. There were some difficulties
//! around the way that ring does not give access to the raw bytes output by
//! these algorithms

use crypto::hkdf::{hkdf_extract,hkdf_expand};
use crypto::sha2::Sha512;

const SHA512_OUTPUT_BYTES_LENGTH: usize = 64;

/// runs HKDF_Extract as specified in
/// [RFC5869](https://tools.ietf.org/html/rfc5869).
pub fn extract(seed: &[u8], secret: &[u8], out: &mut Vec<u8>) {
    if out.len() != SHA512_OUTPUT_BYTES_LENGTH {
        copy_into_cleared(&[0; SHA512_OUTPUT_BYTES_LENGTH], out);
    }
    hkdf_extract(Sha512::new(), &seed, &secret, out)
}

/// runs HKDF_Expand as specified in
/// [RFC5869](https://tools.ietf.org/html/rfc5869). The value of `prk`
/// should be uniformly sampled bytes
pub fn expand(prk: &[u8], info: &[u8], out: &mut Vec<u8>) {
    hkdf_expand(Sha512::new(), &prk, &info, out)
}

/// Moves the contents of `src` into the provided output buffer `dst`. Clears
/// the contents of `dst` first.
fn copy_into_cleared(src: &[u8], dst: &mut Vec<u8>) {
    dst.clear();
    dst.extend_from_slice(src)
}