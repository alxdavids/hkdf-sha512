//! The hkdf module provides access to the functionality provoided HKDF as
//! specified in [RFC5869](https://tools.ietf.org/html/rfc5869)
//!
//! A wrapper around the rust-crypto implementation of HKDF
//! [RFC5869](https://tools.ietf.org/html/rfc5869) locked to using SHA512 as the
//! underlying hash function. Focuses on splitting the `extract` and `expand`
//! functionality.
//!
//! TODO: Rewrite to use the ring implementation. There were some difficulties
//! around the way that ring does not give access to the raw bytes output by
//! these algorithms
///
/// # Examples
///
/// Run using specific instantiation:
/// ```
/// use hkdf_sha512::Hkdf;
/// use rand::rngs::OsRng;
/// use rand_core::RngCore;
///
/// let hkdf = Hkdf{};
///
/// // extract bytes from random seed
/// let mut rng = OsRng;
/// let mut seed = vec![0; 32]; // length of seed determines security
/// rng.fill_bytes(&mut seed);
/// let mut out = Vec::new(); // output buffer will be resized by extract
/// hkdf.extract(&seed, "some_secret_info".as_bytes(), &mut out); // out corresponds to raw PRK
///
/// // expand into output using raw PRK
/// let expand_len = 70; // length of output buffer required
/// let mut exp_out = vec![0; expand_len];
/// hkdf.expand(&out, "some_info".as_bytes(), &mut exp_out);
/// ```
///
/// Can also run using methods directly:
/// ```
/// use hkdf_sha512::{extract,expand};
/// use rand::rngs::OsRng;
/// use rand_core::RngCore;
///
/// // extract bytes from random seed
/// let mut rng = OsRng;
/// let mut seed = vec![0; 32]; // length of seed determines security
/// rng.fill_bytes(&mut seed);
/// let mut out = Vec::new(); // output buffer will be resized by extract
/// extract(&seed, "some_secret_info".as_bytes(), &mut out); // out corresponds to raw PRK
///
/// // expand into output using raw PRK
/// let expand_len = 70; // length of output buffer required
/// let mut exp_out = vec![0; expand_len];
/// expand(&out, "some_info".as_bytes(), &mut exp_out);
/// ```

use crypto::hkdf::{hkdf_extract,hkdf_expand};
use crypto::sha2::Sha512;

const SHA512_OUTPUT_BYTES_LENGTH: usize = 64;

/// A wrapper around the HKDF functionality in cases where it is required that
/// you return a specific instance of HKDF.
///
/// (largely redundant as we only support SHA-512)
pub struct Hkdf{}

impl Hkdf {
    /// extract for specific HKDF invocation
    pub fn extract(&self, seed: &[u8], secret: &[u8], out: &mut Vec<u8>) {
        extract(seed, secret, out)
    }

    /// expand for specific HKDF invocation
    pub fn expand(&self, prk: &[u8], info: &[u8], out: &mut Vec<u8>) {
        expand(prk, info, out)
    }
}

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