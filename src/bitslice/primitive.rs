//! Primitive integers which can be used as the underlying storage for a `Bitslice`.

use core::{cmp, mem};

use try_from::TryFrom;

use crate::util::bitmask;
use crate::aes::ops::{BlockRepr, ShiftRows, MixColumns};
use super::bitslice::{Bitslice, apply_stride_1, apply_stride_2, apply_stride_4};

pub trait BitsliceRepr: Sized {
    fn to_bitslice_order(bs: &mut [Self; 8]);
    fn to_byte_order(bs: &mut [Self; 8]);
}

impl BitsliceRepr for u64 {
    define_function_of_involutions_with_inverse! {
        #[inverse = to_byte_order]
        fn to_bitslice_order(bs: &mut [u64; 8]) {
            // Reorder bytes to be the transpose of the desired bit ordering.
            apply_stride_1(bs, |a, b| u64::swap_move(a, b, 3));
            apply_stride_1(bs, |a, b| u64::swap_move(a, b, 4));
            apply_stride_1(bs, |a, b| u64::swap_move(a, b, 5));

            bs.swap(1, 4);
            bs.swap(3, 6);

            bs.swap(1, 2);
            bs.swap(5, 6);

            // Separates every other nibble, then pair, then individual bit to
            // isolate each bit position. As a side-effect, this transposes the
            // matrix of bytes.
            apply_stride_4(bs, |a, b| u64::swap_move(a, b, 2));
            apply_stride_2(bs, |a, b| u64::swap_move(a, b, 1));
            apply_stride_1(bs, |a, b| u64::swap_move(a, b, 0));
        };
    }
}

impl BitsliceRepr for u32 {
    define_function_of_involutions_with_inverse! {
        #[inverse = to_byte_order]
        fn to_bitslice_order(bs: &mut [u32; 8]) {
            bs.swap(2, 4);
            bs.swap(3, 5);

            bs.swap(1, 2);
            bs.swap(5, 6);

            apply_stride_1(bs, |a, b| u32::swap_move(a, b, 0));
            apply_stride_2(bs, |a, b| u32::swap_move(a, b, 1));
            apply_stride_4(bs, |a, b| u32::swap_move(a, b, 2));
        }
    }
}

impl BitsliceRepr for u16 {
    define_function_of_involutions_with_inverse! {
        #[inverse = to_byte_order]
        fn to_bitslice_order(bs: &mut [u16; 8]) {
            apply_stride_1(bs, |a, b| u16::swap_move(a, b, 3));

            bs.swap(1, 2);
            bs.swap(5, 6);

            bs.swap(2, 4);
            bs.swap(3, 5);

            apply_stride_4(bs, |a, b| u16::swap_move(a, b, 2));
            apply_stride_2(bs, |a, b| u16::swap_move(a, b, 1));
            apply_stride_1(bs, |a, b| u16::swap_move(a, b, 0));
        }
    }
}

const SWAP_MOVE_MASK: [u64; 6] = [
    bitmask(0b01010101, 8),
    bitmask(0b00110011, 8),
    bitmask(0b00001111, 8),
    bitmask(0x00ff00ff, 32),
    bitmask(0x0000ffff, 32),
    0xffff_ffff,
];

pub trait SwapMove {
    /// Swaps `n`-bit windows between two registers so that `hi` contains the most-signifcant
    /// window of `hi`, the most-significant window of `lo`, the thirdmost-signifcant window of
    /// `hi`, etc.
    ///
    /// This function is its own inverse (involution).
    ///
    /// |     | `hi`                 | `lo`                | `n`               |
    /// | --- | -------------------- | ------------------- | ---------------   |
    /// | In  | `ABCDEFGH_IJKLMNOP`  | `abcdefgh_ijklmnop` | `4 == 0b00001111` |
    /// | Out | `ABCDabcd_IJKLijkl`  | `EFGHefgh_MNOPmnop` |                   |
    fn swap_move(lo: &mut Self, hi: &mut Self, log2_n: usize);
}

/// Constants which depend on the size of a `Bitslice`.
///
/// These methods return `u64` instead of `W` directly since `const fn`s cannot have bounds on
/// generic parameters.
///
/// ```text
/// a0 b0 c0 d0
/// a1 b1 c1 d1
/// a2 b2 c2 d2
/// a3 b3 c3 d3
/// ```
impl<W> Bitslice<W> {
    /// The distance between two adjacent columns in the same AES block in a `Bitslice`.
    pub const fn col_shift() -> usize {
        Self::num_blocks()
    }

    /// The distance between two adjacent rows in the same AES block in a `Bitslice`.
    pub const fn row_shift() -> usize {
        4 * Self::col_shift()
    }
    /// The bits corresponding to the first byte (`a0`) in every block.
    pub const fn first_byte() -> u64 {
        (1 << Self::num_blocks()) - 1
    }

    /// The bits corresponding to the first row (`{a-d}0`) in every block.
    pub const fn first_row() -> u64 {
        (1 << Self::row_shift()) - 1
    }

    /// The bits corresponding to the first column (`a{0-3}`) in every block.
    pub const fn first_col() -> u64 {
        bitmask(Self::first_byte(), Self::row_shift())
    }

    /// The bits corresponding to the last column (`d{0-3}`) in every block.
    pub const fn last_col() -> u64 {
        Self::first_col() << (3 * Self::col_shift())
    }

    /// The bits corresponding to all 16 bytes of the first block.
    pub const fn first_block() -> u64 {
        bitmask(1, Self::col_shift())
    }

    pub const fn nth_col_mask(n: usize) -> u64 {
        Self::first_col() << (n * Self::col_shift())
    }
}

macro_rules! primitive {
    ($( $T:ident => $len:expr ),* $(,)*) => {
        $(
            impl SwapMove for $T {
                fn swap_move(lo: &mut $T, hi: &mut $T, log2_n: usize) {
                    let n = 1u32 << log2_n;
                    assert!(n <= 64);

                    let mask = SWAP_MOVE_MASK[log2_n] as $T;
                    let tmp = ((*lo >> n) ^ *hi) & mask;
                    *hi ^= tmp;
                    *lo ^= tmp << n;
                }
            }

            impl BlockRepr for Bitslice<$T> {
                const NUM_BLOCKS: usize = Self::num_blocks();

                fn copy_to_slice(&self, out: &mut [u8]) {
                    let bytes = self.into_bytes();
                    out.copy_from_slice(&bytes[..out.len()]);
                }
            }

            impl From<[u8; $len]> for Bitslice<$T> {
                fn from(bytes: [u8; $len]) -> Self {
                    const WORD_LEN: usize = mem::size_of::<$T>();

                    let mut words = [0; 8];
                    for (i, word) in bytes.chunks_exact(WORD_LEN).enumerate() {
                        words[i] = $T::from_le_bytes(*slice_as_array_ref!(word, WORD_LEN).unwrap());
                    }

                    $T::to_bitslice_order(&mut words);
                    Bitslice(words)
                }
            }

            impl From<Bitslice<$T>> for [u8; $len] {
                fn from(Bitslice(mut words): Bitslice<$T>) -> Self {
                    $T::to_byte_order(&mut words);

                    for word in &mut words {
                        *word = $T::to_le(*word);
                    }

                    unsafe { mem::transmute(words) }
                }
            }

            #[cfg(test)]
            impl IntoIterator for Bitslice<$T> {
                type Item = u8;
                type IntoIter = std::vec::IntoIter<u8>;

                fn into_iter(self) -> Self::IntoIter {
                    Vec::from(&self.into_bytes()[..])
                        .into_iter()
                }
            }

            impl TryFrom<&[u8]> for Bitslice<$T> {
                type Err = usize;

                fn try_from(bytes: &[u8]) -> Result<Self, Self::Err> {
                    if bytes.len() != Self::num_bytes() {
                        return Err(Self::num_bytes());
                    }

                    let mut buf = [0; Bitslice::<$T>::num_bytes()];
                    buf.copy_from_slice(bytes);
                    Ok(buf.into())
                }
            }

            impl Bitslice<$T> {
                pub fn from_bytes(arr: [u8; $len]) -> Self {
                    arr.into()
                }

                pub fn into_bytes(&self) -> [u8; $len] {
                    (*self).into()
                }

                pub fn from_slice(s: &[u8]) -> Self {
                    let len = cmp::min(s.len(), Self::num_bytes());
                    let mut buf = [0; Self::num_bytes()];
                    buf[..len].copy_from_slice(&s[..len]);
                    buf.into()
                }

                fn _shift_rows(&mut self, shifts: impl Clone + Iterator<Item = usize>) {
                    //       a3, a2, a1, a0 < lsb    a3, a2, a1, a0
                    //       b3, b2, b1, b0          b0, b3, b2, b1  (row >> 1) | (row << 3)
                    //       c3, c2, c1, c0    =>    c1, c0, c3, c2  (row >> 2) | (row << 2)
                    // msb > d3, d2, d1, d0          d2, d1, d0, d3  (row >> 3) | (row << 1)
                    for word in self.iter_mut() {
                        let mut out = *word & (Self::first_row() as $T);
                        for (shift, i) in shifts.clone().zip(1..4) {
                            let row_mask = (Self::first_row() << (i * Self::row_shift())) as $T;
                            let row = *word & row_mask;

                            let right = row >> (shift     * Self::col_shift());
                            let left  = row << ((4-shift) * Self::col_shift());
                            out |= (right | left) & row_mask;
                        }

                        *word = out;
                    }
                }
            }

            impl ShiftRows for Bitslice<$T> {
                fn shift_rows(&mut self) {
                    self._shift_rows(1..4);
                }

                fn inv_shift_rows(&mut self) {
                    self._shift_rows((1..4).rev());
                }
            }

            impl MixColumns for Bitslice<$T> {
                fn mix_columns(&mut self) {
                    let Bitslice(b) = self;
                    let a = gf_polyval4!(2*b[0] ^ 3*b[1] ^ 1*b[2] ^ 1*b[3]);
                    *self = Bitslice(a);
                }

                fn inv_mix_columns(&mut self) {
                    let Bitslice(b) = self;
                    let a = gf_polyval4!(14*b[0] ^ 11*b[1] ^ 13*b[2] ^ 9*b[3]);
                    *self = Bitslice(a);
                }
            }
        )*
    }
}

primitive! {
    u16 => 16,
    u32 => 32,
    u64 => 64,
}
