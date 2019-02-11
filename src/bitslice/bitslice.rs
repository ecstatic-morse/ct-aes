use core::{fmt, mem, ops};

use crate::aes::{self, ops::AddRoundKey};
use crate::word::{MachineWord as Word};

/// A `Bitslice` stores a series of bytes across 8 machine words, using the 0th word to store the
/// least-significant bit of each byte and the 7th word to store the most-significant bit.
///
/// As a result, A `Bitslice` can store up to `n` bytes where `n` is the number of bits in a
/// machine word.
///
/// The order of bits in a single word is not the same as the order of bytes as they appear in
/// memory. Instead, we store bits corresponding to the same row and column in each AES block next
/// to one another. This makes some AES operations more efficient. For example, on 32-bit machines
/// (which can store 2 AES blocks per `Bitslice`), a byte stream is mapped to a `Bitslice` in the
/// following way:
///
/// ```text
///               Block 0         Block 1
///             0  4  8 12      16 20 24 28
/// Byte        1  5  9 13      17 21 25 29
/// Stream      2  6 10 14      18 22 26 30
///             3  7 11 15      19 23 27 31
///
///           row    |             Row A             |             Row B             |
/// Bit       column | Col 0 | Col 1 | Col 2 | Col 3 | Col 0 | Col 1 | Col 2 | Col 3 |
/// Slice     block  | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 1 | ...
///           order  | 0  16   4  20   8  24  12  28   1  17   5  21   9  25  13  29 |
///                   lsb                            ->                           msb
/// ```
///
/// 64-bit machines store 4 AES blocks per `Bitslice`, so the order of bytes would be
/// `0, 16, 32, 48, 4, 20, 36, 52, ...`.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub struct Bitslice<W = Word>(pub(crate) [W; 8]);

impl<W> Bitslice<W> {
    /// The number of bytes which can be stored in a single `Bitslice`.
    pub const fn num_bytes() -> usize {
        8 * mem::size_of::<W>()
    }

    /// The number of AES blocks which can be stored in a single  `Bitslice`.
    pub const fn num_blocks() -> usize {
        Self::num_bytes() / aes::BLOCK_LEN
    }
}

impl<W> Bitslice<W> {
    pub fn iter(&self) -> impl Iterator<Item = &W> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut W> {
        self.0.iter_mut()
    }
}

#[cfg(test)]
impl<W> Bitslice<W> {
    /// Returns the index of the bit which corresponds to the given byte in a series of AES blocks.
    #[allow(dead_code)]
    fn byte_to_bit_index(n: usize) -> usize {
        let block = n / aes::BLOCK_LEN;
        let byte =  n % aes::BLOCK_LEN;

        let col = byte / 4;
        let row = byte % 4;

        16 * row + 4 * col + block
    }

    fn bit_to_byte_index(n: usize) -> usize {
        let block = n % Self::num_blocks();
        let byte = n / Self::num_blocks();

        let col = byte % 4;
        let row = byte / 4;

        16 * block + 4 * col + row
    }

    /// Returns the index of the byte to which each bit corresponds.
    fn bit_indexes() -> impl Iterator<Item = usize> {
        (0..Self::num_bytes()).map(Self::bit_to_byte_index)
    }

    /// Gets the value stored in the `n`-th position of the `Bitslice`.
    ///
    /// For example, `get(0)` gets the byte held in the least-significant bit of each word.
    fn get(&self, n: usize) -> u8
        where W: Copy + Into<u128>,
    {
        assert!(n < Self::num_bytes());

        let mut ret = 0u8;
        for (i, &bits) in self.iter().enumerate() {
            let bit = ((bits.into() >> n) & 1) as u8;
            ret |= bit << i;
        }

        ret
    }
}

impl fmt::Debug for Bitslice<Word> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.into_bytes();
        writeln!(f, "[")?;
        for block in 0..Self::num_blocks() {
            for row in 0..4 {
                for col in 0..4 {
                    let b = bytes[aes::BLOCK_LEN*block + row + 4*col];
                    write!(f, "0x{:02x}, ", b)?;
                }
                writeln!(f)?;
            }
            writeln!(f)?;
        }
        writeln!(f, "]")
    }
}

impl<W> ops::BitXor for Bitslice<W>
    where W: Copy + ops::BitXorAssign
{
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl<W> ops::BitXorAssign for Bitslice<W>
    where W: Copy + ops::BitXorAssign
{
    fn bitxor_assign(&mut self, rhs: Self) {
        for (l, &r) in self.iter_mut().zip(rhs.iter()) {
            *l ^= r;
        }
    }
}

impl<W> AddRoundKey for Bitslice<W>
    where W: Copy + ops::BitXorAssign
{
    type RoundKey = RoundKey<W>;

    fn add_round_key(&mut self, rk: &Self::RoundKey) {
        *self ^= rk.0
    }
}

/// A `Bitslice` which stores a single 128-bit round key.
///
/// On platforms with registers larger than 16 bits, a single `Bitslice` could hold more than one
/// round key. However, because we are encrypting blocks in parallel, we duplicate a single round
/// key across each block of the underlying `Bitslice`, so parallel `AddRoundKey` is a simple XOR.
///
/// The first word of the round key is stored in the first row of the `Bitslice`.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct RoundKey<W = Word>(Bitslice<W>);

impl<W> fmt::Debug for RoundKey<W>
    where Bitslice<W>: fmt::Debug
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("RoundKey")
            .field(&self.0)
            .finish()
    }
}

impl From<RoundKey<Word>> for aes::Block {
    fn from(rk: RoundKey<Word>) -> Self {
        use try_from::TryFrom;

        aes::Block::try_from(&rk.0.into_bytes()[..aes::BLOCK_LEN]).unwrap()
    }
}

impl<'a> From<&'a aes::Block> for RoundKey<Word> {
    fn from(block: &'a aes::Block) -> Self {
        Self::from_key(block.as_ref())
    }
}

impl RoundKey<Word> {
    /// Creates a `RoundKey` where every column of each block is `[rc, 0, 0, 0]`.
    pub const fn from_rc(rc: u8) -> Self {
        const fn bit(byte: u8, bit: usize) -> Word {
            const OUT: [Word; 2] = [0, !0];
            OUT[((byte >> bit) & 1) as usize]
        }

        RoundKey(Bitslice([
             bit(rc, 0) & Bitslice::<Word>::first_row() as Word,
             bit(rc, 1) & Bitslice::<Word>::first_row() as Word,
             bit(rc, 2) & Bitslice::<Word>::first_row() as Word,
             bit(rc, 3) & Bitslice::<Word>::first_row() as Word,
             bit(rc, 4) & Bitslice::<Word>::first_row() as Word,
             bit(rc, 5) & Bitslice::<Word>::first_row() as Word,
             bit(rc, 6) & Bitslice::<Word>::first_row() as Word,
             bit(rc, 7) & Bitslice::<Word>::first_row() as Word,
        ]))
    }

    /// Creates a round key directly from up to 16 bytes of key material.
    pub fn from_key(key: &[u8]) -> Self {
        assert!(key.len() <= aes::BLOCK_LEN);

        // TODO: optimize by only copying the key material once and shifting the resulting
        // bitslice.
        let mut buf = [0; Bitslice::<Word>::num_bytes()];
        for out in buf.chunks_exact_mut(aes::BLOCK_LEN) {
            out[..key.len()].copy_from_slice(key);
        }

        RoundKey(buf.into())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Word> {
        self.0.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Word> {
        self.0.iter_mut()
    }

    /// Perform `SubBytes` on the round key.
    pub fn sub_word(&mut self) {
        use crate::aes::ops::SubBytes;

        self.0.sub_bytes()
    }

    /// Rotates each word in the round key left by one.
    pub fn rot_word(&mut self) {
        for w in self.iter_mut() {
            *w = w.rotate_right((1 * Bitslice::<Word>::row_shift()) as u32);
        }
    }
}

impl ops::BitXor for RoundKey {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl ops::BitXorAssign for RoundKey {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

macro_rules! apply {
    ( $(
        $fn:ident => [
            ($b0:tt, $b1:tt),
            ($b2:tt, $b3:tt),
            ($b4:tt, $b5:tt),
            ($b6:tt, $b7:tt) $(,)*
        ]
    );* $(;)* ) => {
        $(
            pub(crate) fn $fn<W, F>(bits: &mut [W; 8], f: F)
                where F: Fn(&mut W, &mut W)
            {
                let [b0, b1, b2, b3, b4, b5, b6, b7] = bits;
                let b = (b0, b1, b2, b3, b4, b5, b6, b7);
                f(b.$b0, b.$b1);
                f(b.$b2, b.$b3);
                f(b.$b4, b.$b5);
                f(b.$b6, b.$b7);
            }
        )*
    }
}

apply! {
    apply_stride_1 => [(0, 1), (2, 3), (4, 5), (6, 7)];
    apply_stride_2 => [(0, 2), (1, 3), (4, 6), (5, 7)];
    apply_stride_4 => [(0, 4), (1, 5), (2, 6), (3, 7)];
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;
    use std::io::Read;

    use try_from::TryFrom;

    use crate::util::test::{RngReadAdapter, RoundTrip};
    use super::*;

    type Bs = Bitslice<Word>;

    #[test]
    fn order_sanity_check() {
        fn order<T>(n: usize) -> Vec<usize> {
            Bitslice::<T>::bit_indexes().take(n).collect()
        }

        assert_eq!(order::<u16>(9),  &[0,  4, 8, 12, 1,  5,  9, 13, 2, /* ... */]);
        assert_eq!(order::<u32>(10), &[0, 16, 4, 20, 8, 24, 12, 28, 1, 17, /* ... */]);
        assert_eq!(order::<u64>(9),  &[0, 16, 32, 48, 4, 20, 36, 52, 8, /* ... */]);
    }

    fn iota(n: usize) -> Vec<u8> {
        assert!(n < 256);
        (0..n).map(|x| x as u8).collect()
    }

    #[test]
    fn order() {
        fn _order<T>()
            where T: Copy + Into<u128>,
                  Bitslice<T>: for<'a> TryFrom<&'a [u8], Err = usize>,
        {
            let expected: Vec<u8> = Bitslice::<T>::bit_indexes()
                .map(|i| i as u8)
                .collect();

            let iota = iota(Bitslice::<T>::num_bytes());
            let bitslice = Bitslice::<T>::try_from(&iota).unwrap();
            let actual: Vec<u8> = (0..Bitslice::<T>::num_bytes())
                .map(|i| bitslice.get(i))
                .collect();

            assert_eq!(&actual, &expected);
        }

        _order::<u16>();
        _order::<u32>();
        _order::<u64>();
    }

    #[test]
    fn conversion() {
        let iota = iota(Bs::num_bytes());
        let bs = Bs::from_slice(&iota);

        assert_eq!(&bs.into_bytes()[..], &iota[..]);
    }

    #[test]
    fn shift_rows() {
        RoundTrip::<Bs>::shift_rows()
            .comparison_test(
                RoundTrip::<aes::Block>::shift_rows(),
                RngReadAdapter::default().take(65536),
                Bs::num_blocks());
    }

    #[test]
    fn mix_columns() {
        RoundTrip::<Bs>::mix_columns()
            .comparison_test(
                RoundTrip::<aes::Block>::mix_columns(),
                RngReadAdapter::default().take(65536),
                Bs::num_blocks());
    }

    #[test]
    fn sub_bytes() {
        RoundTrip::<Bs>::sub_bytes()
            .comparison_test(
                RoundTrip::<aes::Block>::sub_bytes(),
                RngReadAdapter::default().take(65536),
                Bs::num_blocks());
    }
}
