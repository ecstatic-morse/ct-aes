//! Operations on the 16-byte AES block.

use core::{fmt, ops};

use try_from::TryFrom;

/// The number of bytes in an AES block.
pub const BLOCK_LEN: usize = 16;

type BlockArray = [u8; BLOCK_LEN];

/// A byte array with the same length as an AES block.
///
/// Bytes are stored in column-major order.
///
///```text
///  0  4  8 12
///  1  5  9 13
///  2  6 10 14
///  3  7 11 15
///```
#[derive(Clone, Copy, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Block(pub BlockArray);

fn idx(row: usize, col: usize) -> usize {
    debug_assert!(row < 4);
    debug_assert!(col < 4);

    row + 4*col
}

/// Indexes a block by row, then column.
impl ops::Index<(usize, usize)> for Block {
    type Output = u8;

    fn index(&self, (row, col): (usize, usize)) -> &Self::Output {
        &self.0[idx(row, col)]
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:x}", byte)?;
        }

        Ok(())
    }
}


/// Indexes a block by row, then column.
impl ops::IndexMut<(usize, usize)> for Block {
    fn index_mut(&mut self, (row, col): (usize, usize)) -> &mut Self::Output {
        &mut self.0[idx(row, col)]
    }
}

impl TryFrom<&[u8]> for Block {
    type Err = ();

    fn try_from(s: &[u8]) -> Result<Self, Self::Err> {
        slice_as_array_ref!(s, BLOCK_LEN)
            .map(|&b| Block(b))
    }
}

impl From<BlockArray> for Block {
    fn from(arr: BlockArray) -> Self {
        Block(arr)
    }
}

impl From<Block> for BlockArray {
    fn from(block: Block) -> Self {
        block.0
    }
}

impl AsRef<[u8]> for Block {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Block {
    /// Iterates over the bytes in a block.
    pub fn iter(&self) -> impl '_ + Iterator<Item = &u8> {
        self.0.iter()
    }

    /// Iterates over the bytes in a block.
    pub fn iter_mut(&mut self) -> impl '_ + Iterator<Item = &mut u8> {
        self.0.iter_mut()
    }

    /// Creates a new `Block` from a byte array in row major order.
    pub fn from_row_major(bytes: BlockArray) -> Block {
        let mut block = Block(bytes);
        block.transpose();
        block
    }

    /// Transposes an AES block in-place.
    ///
    /// The first row becomes the first column, etc.
    pub fn transpose(&mut self) {
        for row in 0..4 {
            for col in (row+1)..4 {
                self.0.swap(idx(row, col), idx(col, row));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_major_order() {
        assert_eq!(idx(0, 3), 12);
        assert_eq!(idx(3, 0), 3);
        assert_eq!(idx(1, 2), 9);
    }

    #[test]
    fn transpose() {
        let mut block = Block::from([
             0,  4,  8, 12,
             1,  5,  9, 13,
             2,  6, 10, 14,
             3,  7, 11, 15,
        ]);

        block.transpose();
        assert_eq!(block, Block::from([
             0,  1,  2,  3,
             4,  5,  6,  7,
             8,  9, 10, 11,
            12, 13, 14, 15,
        ]));
    }
}
