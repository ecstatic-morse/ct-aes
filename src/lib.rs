//! **This library is a WORK IN PROGRESS. It is INSECURE and should not be used by ANYONE.**
//!
//! Timing-attack resistant AES encryption.
//!
//! This crate implements the AES block cipher using methods which are resistant to timing attacks.
//! The fastest, non-parallel, software algorithm uses a 4kB lookup table which is vulnerable to
//! [cache-based side-channel attacks][t-table]. In practice, this is not a major security
//! vulnerability since most widely-used platforms use custom assembly routines for encryption.
//!
//! [t-table]: https://access.redhat.com/blogs/766093/posts/1976303
//!
//! Many modern processors have dedicated hardware for AES encryption.
//!
//! -  Bitslicing
//!     - 16-bit ✓
//!     - 32-bit ✓
//!     - 64-bit ✓
//!     - 128-bit ✗
//! - Vector Permutation
//!     - 128-bit ✗
//!     - 256-bit ✗
//! - Hardware
//!     - x86 ✓
//!     - x86-64 ✓

#![cfg_attr(not(test), no_std)]

#[macro_use] mod util;

pub mod aes;
pub mod bitslice;
pub mod hardware;
mod word;

pub use self::aes::Key;

use core::cmp;

type Result<T> = core::result::Result<T, ()>;

/// An initialized key schedule which can perform block encryption and decryption.
pub trait BlockCipher {
    /// Encrypt the input data, returning the number of bytes encrypted.
    ///
    /// `blocks.len()` must be a multiple of the AES block length (16 bytes).
    fn encrypt_blocks(&self, blocks: &mut [u8]) -> usize;

    /// Decrypt the input data, returning the number of bytes decrypt.
    ///
    /// `blocks.len()` must be a multiple of the AES block length (16 bytes).
    fn decrypt_blocks(&self, blocks: &mut [u8]) -> usize;
}

/// A `BlockCipher` which can work faster if allowed to encrypt blocks in parallel.
pub trait ParallelBlockCipher: BlockCipher {
    /// The maximum parallelism of this AES implementation.
    const PARALLEL_BLOCKS: usize;

    /// The number of bytes which will be encrypted/decrypted at one time if a slice with the given
    /// length is passed as an argument to `{en,de}crypt_blocks`.
    fn bytes_encrypted(len: usize) -> usize {
        cmp::min(len, Self::PARALLEL_BLOCKS)
    }
}
