//! Symbolic arithmetic in GF(2⁸).

use std::ops;

/// Generates a symbolic multiplication table in GF(2⁸) for all constants up to a given limit.
///
/// ## Example Multiplication Table
///
/// | bit | b  | 2 • b   | 3 • b        |
/// | --- | -- | ------- | ------------ |
/// |  0  | b₀ | b₇      | b₀ ⊕ b₇      |
/// |  1  | b₁ | b₀ ⊕ b₇ | b₀ ⊕ b₁ ⊕ b₇ |
/// |  2  | b₂ | b₁      | b₁ ⊕ b₂      |
/// |  3  | b₃ | b₂ ⊕ b₇ | b₂ ⊕ b₃ ⊕ b₇ |
/// |  4  | b₄ | b₃ ⊕ b₇ | b₃ ⊕ b₄ ⊕ b₇ |
/// |  5  | b₅ | b₄      | b₄ ⊕ b₅      |
/// |  6  | b₆ | b₅      | b₅ ⊕ b₆      |
/// |  7  | b₇ | b₆      | b₆ ⊕ b₇      |
pub fn multiplication_table(up_to: usize) -> Vec<Multiple> {
    let mut ret = vec![Multiple::default()];

    for i in 1..up_to {
        let x = if i % 2 == 1 {
            ret[i-1].increment()
        } else {
            ret[i/2].double()
        };

        ret.push(x);
    }

    ret
}

/// A symbolic representation of a constant multiple of an element in GF(2⁸).
///
/// Each coefficient of the resulting product is stored as a sum of bits of the input element.
#[derive(Clone, Copy, Debug, Default)]
pub struct Multiple([BitSet; 8]);

impl Multiple {
    pub fn coefficients(&self) -> impl Iterator<Item = &BitSet> {
        self.0.iter()
    }

    fn increment(self) -> Self {
        let Multiple(mut x) = self;
        for i in 0..8 {
            x[i] ^= BitSet::with_single_bit(i as u8);
        }

        Multiple(x)
    }

    fn double(self) -> Self {
        let Multiple(mut x) = self;

        // double
        x.rotate_right(1);

        // reduce mod 11b
        x[1] ^= x[0];
        x[3] ^= x[0];
        x[4] ^= x[0];

        Multiple(x)
    }
}

/// A set which can contain any combination of the integers in [0, 8). 
#[derive(Clone, Copy, Debug, Default)]
pub struct BitSet(u8);

impl ops::BitXor for BitSet {
    type Output = Self;

    fn bitxor(mut self, other: Self) -> Self {
        self ^= other;
        self
    }
}

impl ops::BitXorAssign for BitSet {
    fn bitxor_assign(&mut self, other: Self) {
        self.0 ^= other.0
    }
}

impl BitSet {
    fn with_single_bit(bit: u8) -> Self {
        BitSet(1 << bit)
    }

    pub fn bits(&self) -> impl Iterator<Item = u8> {
        let BitSet(set) = *self;
        (0..8).filter(move |bit| (set >> bit) & 1 != 0)
    }
}

