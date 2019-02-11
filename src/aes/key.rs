//! Types for storing AES key material.

use core::cmp;

use try_from::TryFrom;

use crate::{aes, BlockCipher};
use crate::aes::ops::AddRoundKey;

/// The round constants used for key expansion.
pub const ROUND_CONSTANTS: [u8; 10] = [
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// A secret key which has not yet been expanded.
///
/// Must be either 128, 192, or 256 bits long.
#[derive(Clone, Copy)]
pub enum Key<'a> {
    /// A 128-bit key.
    Aes128(&'a [u8; 16]),

    /// A 192-bit key.
    Aes192(&'a [u8; 24]),

    /// A 256-bit key.
    Aes256(&'a [u8; 32]),
}

impl Key<'_> {
    /// Creates a `Key` from a byte slice.
    ///
    /// The slice must be either 16, 24, or 32 bytes long.
    pub fn from_bytes(key: &[u8]) -> crate::Result<Self> {
        let key = match key.len() {
            16 => Key::Aes128(slice_as_array_ref!(key, 16).unwrap()),
            24 => Key::Aes192(slice_as_array_ref!(key, 24).unwrap()),
            32 => Key::Aes256(slice_as_array_ref!(key, 32).unwrap()),

            _ => return Err(()),
        };

        Ok(key)
    }

    /// Returns the number of rounds which should be used for a key of this length.
    pub fn rounds(&self) -> usize {
        match self {
            Key::Aes128(_) => 10,
            Key::Aes192(_) => 12,
            Key::Aes256(_) => 14,
        }
    }

    /// The number of 128-bit round keys used for encryption with a key of this length.
    pub fn num_round_keys(&self) -> usize {
        self.rounds() + 1
    }

    /// Returns the length of this key in bytes.
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// A byte slice containing the key material.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Key::Aes128(a) => &a[..],
            Key::Aes192(a) => &a[..],
            Key::Aes256(a) => &a[..],
        }
    }
}

impl AsRef<[u8]> for Key<'_> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// A generic container for round keys.
#[derive(Clone, Copy)]
pub enum Schedule<R: AddRoundKey> {
    /// The round keys for a 128-bit key.
    Aes128([R::RoundKey; 11]),

    /// The round keys for a 192-bit key.
    Aes192([R::RoundKey; 13]),

    /// The round keys for a 256-bit key.
    Aes256([R::RoundKey; 15]),
}

impl<R: AddRoundKey> Schedule<R>
    where R::RoundKey: Copy
{
    /// Creates a zero-initialized key schedule with the same length as the given key.
    pub fn new(key: Key) -> Self where R::RoundKey: Default {
        Self::fill_with(key, R::RoundKey::default())
    }

    /// Creates a key schedule with the same length as the given key containing copies of the given
    /// round key.
    pub fn fill_with(key: Key, rk: R::RoundKey) -> Self {
        match key {
            Key::Aes128(_) => Schedule::Aes128([rk; 11]),
            Key::Aes192(_) => Schedule::Aes192([rk; 13]),
            Key::Aes256(_) => Schedule::Aes256([rk; 15]),
        }
    }
}

impl<R> BlockCipher for Schedule<R>
    where R: aes::ops::Aes + aes::ops::BlockRepr + for<'a> TryFrom<&'a [u8]>
{
    fn encrypt_blocks(&self, bytes: &mut [u8]) -> usize {
        let len = cmp::min(bytes.len(), R::NUM_BLOCKS * aes::BLOCK_LEN);
        let mut block = R::try_from(&bytes[..len]).ok().unwrap();

        block.encrypt(self.as_ref());

        block.copy_to_slice(&mut bytes[..len]);
        len
    }

    fn decrypt_blocks(&self, bytes: &mut [u8]) -> usize {
        let len = cmp::min(bytes.len(), R::NUM_BLOCKS * aes::BLOCK_LEN);
        let mut block = R::try_from(&bytes[..len]).ok().unwrap();

        block.decrypt(self.as_ref());

        block.copy_to_slice(&mut bytes[..len]);
        len
    }
}

impl<R: AddRoundKey> Schedule<R> {
    /// The round keys in this key schedule.
    pub fn as_slice(&self) -> &[R::RoundKey] {
        match self {
            Schedule::Aes128(s) => s,
            Schedule::Aes192(s) => s,
            Schedule::Aes256(s) => s,
        }
    }

    /// The round keys in this key schedule.
    pub fn as_mut_slice(&mut self) -> &mut [R::RoundKey] {
        match self {
            Schedule::Aes128(s) => s,
            Schedule::Aes192(s) => s,
            Schedule::Aes256(s) => s,
        }
    }
}

impl<R: AddRoundKey> AsRef<[R::RoundKey]> for Schedule<R> {
    fn as_ref(&self) -> &[R::RoundKey] {
        self.as_slice()
    }
}

impl<R: AddRoundKey> AsMut<[R::RoundKey]> for Schedule<R> {
    fn as_mut(&mut self) -> &mut [R::RoundKey] {
        self.as_mut_slice()
    }
}
