//! Types and operations common to all AES implementations.
//!
//! This includes keys, key schedules, and raw AES blocks.

pub mod block;
pub mod key;
#[cfg(test)] pub(crate) mod simple;
pub mod ops;

pub use self::block::{Block, BLOCK_LEN};
pub use self::key::Key;

#[cfg(test)]
include!(concat!(env!("OUT_DIR"), "/sbox.rs"));
