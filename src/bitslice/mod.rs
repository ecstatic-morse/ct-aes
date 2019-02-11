//! AES encryption with [bitslices][].
//!
//! [bitslices]: https://en.wikipedia.org/wiki/Bit_slicing

#[macro_use]
mod gf256;

mod bitslice;
mod key;
mod sbox;
mod primitive;

pub use self::key::Schedule;
pub(crate) use self::bitslice::Bitslice;
