//! Arithmetic in GF(2⁸)/(x⁸ + x⁴ + x³ + x + 1), the finite field used by AES.

use std::ops;

pub mod symbolic;
mod inv;

pub use self::inv::inverse_table;

/// An element of GF(2⁸)/(x⁸ + x⁴ + x³ + x + 1).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Element(pub u8);

impl ops::Add for Element {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl ops::AddAssign for Element {
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl ops::Mul for Element {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl ops::MulAssign for Element {
    fn mul_assign(&mut self, rhs: Self) {
        let Element(mut lhs) = *self;
        let Element(mut rhs) = rhs;

        let mut ret = 0u8;
        for _ in 0..8 {
            if rhs & 1 != 0 {
                ret ^= lhs;
            }

            let will_overflow = lhs & 0x80 != 0;
            lhs <<= 1;
            if will_overflow {
                lhs ^= 0x1b;
            }

            rhs >>= 1;
        }

        self.0 = ret;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mul() {
        assert_eq!(Element(0x53) * Element(0xca), Element(1));
    }
}

