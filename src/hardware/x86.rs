#[macro_use]
mod intrinsics;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as simd;
#[cfg(target_arch = "x86")]
use core::arch::x86 as simd;

use core::{mem, ops};

use try_from::TryFrom;

use crate::BlockCipher;
use crate::aes::{self, Key, ops::{Aes, AddRoundKey}, key::{self, ROUND_CONSTANTS as RCON}};

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Block(simd::__m128i);

impl From<&'_ aes::Block> for Block {
    fn from(bytes: &'_ aes::Block) -> Self {
        let ptr = bytes.as_ref().as_ptr() as *const simd::__m128i;
        unsafe { Block(simd::_mm_loadu_si128(ptr)) }
    }
}

impl From<Block> for aes::Block {
    fn from(block: Block) -> Self {
        unsafe { mem::transmute(block) }
    }
}

impl Aes for Block {
    fn encrypt_round(&mut self, rk: &Self::RoundKey) {
        self.0 = unsafe { simd::_mm_aesenc_si128(self.0, rk.0) };
    }

    fn encrypt_round_last(&mut self, rk: &Self::RoundKey) {
        self.0 = unsafe { simd::_mm_aesenclast_si128(self.0, rk.0) };
    }

    fn decrypt_round(&mut self, rk: &Self::RoundKey) {
        self.0 = unsafe {
            let rk = simd::_mm_aesimc_si128(rk.0);
            simd::_mm_aesdec_si128(self.0, rk)
        };
    }

    fn decrypt_round_last(&mut self, rk: &Self::RoundKey) {
        self.0 = unsafe { simd::_mm_aesdeclast_si128(self.0, rk.0) };
    }
}

impl TryFrom<&[u8]> for Block {
    type Err = ();

    fn try_from(s: &[u8]) -> Result<Self, Self::Err> {
        aes::Block::try_from(s)
            .map(|b| (&b).into())
    }
}

impl ops::BitXor for Block {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl ops::BitXorAssign for Block {
    fn bitxor_assign(&mut self, rhs: Self) {
        unsafe { self.0 = simd::_mm_xor_si128(self.0, rhs.0); }
    }
}

impl AddRoundKey for Block {
    type RoundKey = Self;

    fn add_round_key(&mut self, rhs: &Self) {
        *self ^= *rhs;
    }
}

// TODO: remove once union casts or transmute is stable in const fn.
macro_rules! block_from_bytes {
    ($( $bytes:expr ),* $(,)*) =>  {
        unsafe {
            BlockBytes { bytes: [$( $bytes ),*] }.block
        }
    }
}

macro_rules! block_from_cols {
    ($a:expr, $b:expr, $c:expr, $d:expr) =>  {
        block_from_bytes![
            $a, $a, $a, $a,
            $b, $b, $b, $b,
            $c, $c, $c, $c,
            $d, $d, $d, $d,
        ]
    }
}

union BlockBytes {
    block: Block,
    bytes: [u8; mem::size_of::<Block>()],
}

pub const COL_SHIFT: usize = 4;
pub const ZERO: Block = block_from_cols!(0, 0, 0, 0);

pub type RoundKey = Block;
pub type Schedule = key::Schedule<RoundKey>;

impl BlockCipher for Schedule {
    fn encrypt_blocks(&self, bytes: &mut [u8]) -> usize {
        let round_keys = self.as_slice();
        let mut block = Block::try_from(&bytes[..aes::BLOCK_LEN]).unwrap();

        block.encrypt(round_keys);

        let block = aes::Block::from(block);
        bytes[..aes::BLOCK_LEN].copy_from_slice(block.as_ref());
        aes::BLOCK_LEN
    }

    fn decrypt_blocks(&self, bytes: &mut [u8]) -> usize {
        let round_keys = self.as_slice();
        let mut block = Block::try_from(&bytes[..aes::BLOCK_LEN]).unwrap();

        block.decrypt(round_keys);

        let block = aes::Block::from(block);
        bytes[..aes::BLOCK_LEN].copy_from_slice(block.as_ref());
        aes::BLOCK_LEN
    }
}

impl From<Key<'_>> for Schedule {
    fn from(key: Key<'_>) -> Self {
        match key {
            Key::Aes128(arr) => {
                let mut round_keys = [unsafe { mem::zeroed() }; 11];
                expand_key_128(arr, &mut round_keys);
                key::Schedule::Aes128(round_keys)
            }

            Key::Aes192(arr) => {
                let mut round_keys = [unsafe { mem::zeroed() }; 13];
                expand_key_192(arr, &mut round_keys);
                key::Schedule::Aes192(round_keys)
            }

            Key::Aes256(arr) => {
                let mut round_keys = [unsafe { mem::zeroed() }; 15];
                expand_key_256(arr, &mut round_keys);
                key::Schedule::Aes256(round_keys)
            }
        }
    }
}

/// Given `X := X0, X1, X2, X3`, computes `X0, X0^X1, X0^X1^X2, X0^X1^X2^X3`
fn partial_sum_words(x: Block) -> Block {
    //   X := X0, X1, X2, X3
    //   Z :=  0,  0, X1, X0
    // X^Z  = X0, X1, X1^X2, X0^X3
    //   T :=  0, X0, X0, X1^X2
    // X^T  = X0, X0^X1, X0^X1^X2, X0^X1^X2^X3
    let z = shufps!(ZERO, x, [0, 0, 1, 0]);
    let x = x ^ z;
    let t = shufps!(z, x, [0, 3, 0, 2]);
    x ^ t
}

// keygenassist(X) = Sub(X1), Rot(Sub(X1)), Sub(X3), Rot(Sub(X3))

/// splat_sub_word_3(X) = Sub(X3), Sub(X3), Sub(X3), Sub(X3)
fn splat_sub_word_3(kg: Block) -> Block {
    pshufd!(kg, [2, 2, 2, 2])
}

/// splat_rot_sub_word_3(X) = Rot(Sub(X3)), Rot(Sub(X3)), Rot(Sub(X3)), Rot(Sub(X3))
fn splat_rot_sub_word_3(kg: Block) -> Block {
    pshufd!(kg, [3, 3, 3, 3])
}

// X0           = KG ^ W0
// X1 = X0 ^ W1 = KG ^ W0 ^ W1
// X2 = X1 ^ W2 = KG ^ W0 ^ W1 ^ W2
// X3 = X2 ^ W3 = KG ^ W0 ^ W1 ^ W2 ^ W3
// X4 = X3 ^ W4 = KG ^ W0 ^ W1 ^ W2 ^ W3 ^ W4
// X5 = X4 ^ W5 = KG ^ W0 ^ W1 ^ W2 ^ W3 ^ W4 ^ W5
// X6 = X5 ^ W6 = KG ^ W0 ^ W1 ^ W2 ^ W3 ^ W4 ^ W5 ^ W6
// X7 = X6 ^ W7 = KG ^ W0 ^ W1 ^ W2 ^ W3 ^ W4 ^ W5 ^ W6 ^ W7

macro_rules! expand128 {
    ( $rk:ident => [$( $i:expr ),* $(,)*] ) => {
        $( expand128!($rk[$i], $rk[$i], $rk[$i+1], splat_rot_sub_word_3, RCON[$i]); )*
    };

    ($in:expr, $kg:expr, $out:expr, $splat:path, $rc:expr) => {
        let a = $in;
        let kg = keygenassist!($kg, $rc as i32);
        let kg = $splat(kg);

        let a = partial_sum_words(a);
        let a = a ^ kg;
        $out = a;
    };
}

macro_rules! expand192 {
    ( $rk:ident => [$( $i:expr ),* $(,)*] ) => {
        $( expand192!($rk[3*$i], RCON[2*$i], RCON[2*$i+1]); )*
    };

    ( $rk:ident[$i:expr], $rc1:expr, $rc2:expr ) => {
        // i    i+1  i+2  i+3  i+4
        // aaaa bbMM NNNN OOOO PP..
        let a = $rk[$i];                         // W0, W1, W2, W3
        let b = $rk[$i+1];                       // W4, W5,  0,  0

        let kg1 = keygenassist!(b, $rc1 as i32); // ?, KG, ?, ?
        let kg1 = shufps!(b, kg1, [3, 3, 1, 1]); // 0, 0, KG, KG

        let m = shufps!(b, a, [0, 3, 0, 1]);     // W4, 0, W0, W1
        let tmp = shufps!(b, m, [3, 1, 1, 2]);   //  0, W5, 0, W0
        let m = m ^ tmp;                         // W4, W5, W0, W0^W1
        let m = m ^ kg1;                         // W4, W5, KG^W0, KG^W0^W1
        $rk[$i+1] = m;

        let n = shufps!(a, b, [2, 3, 0, 1]);     // W2, W3, W4, W5
        let n = partial_sum_words(n);            // W2, W2^W3, W2^W3^W4, W2^W3^W4^W5

        let first = pshufd!(m, [3, 3, 3, 3]);    // KG^W0^W1 KG^W0^W1 KG^W0^W1 KG^W0^W1
        let n = n ^ first;
        $rk[$i+2] = n;

        let kg2 = keygenassist!(n, $rc2 as i32); // ?,  ?,  ?,  KG
        let kg2 = splat_rot_sub_word_3(kg2);     // KG, KG, KG, KG

        let o = shufps!(m, n, [2, 3, 0, 1]);     // W0, W1, W2, W3
        let o = partial_sum_words(o);            // W0, W0^W1, W0^W1^W2, W0^W1^W2^W3
        let o = o ^ kg2;
        $rk[$i+3] = o;

        // Relies on dead code elimination to remove this on the final iteration.
        if ($i+4) < 13 {
            let p = shufps!(n, ZERO, [2, 3, 0, 0]); // W4, W5, 0, 0
            let tmp = pshufd!(p, [3, 0, 3, 3]);     //  0, W4, 0, 0
            let p = p ^ tmp;                        // W4, W4^W5, 0, 0
            let last = shufps!(o, p, [3, 3, 3, 3]); // KG^W0^W1^W2^W3, KG^W0^W1^W2^W3, 0, 0
            let p = p ^ last;
            $rk[$i+4] = p;
        }
    };
}

macro_rules! expand256 {
    ( $rk:ident => [$i:expr, $( $tail:expr ),* $(,)*] ) => {
        expand128!($rk[2*$i],   $rk[2*$i+1], $rk[2*$i+2], splat_rot_sub_word_3, RCON[$i]);
        expand128!($rk[2*$i+1], $rk[2*$i+2], $rk[2*$i+3], splat_sub_word_3,     RCON[$i]);
        expand256!($rk => [$( $tail ),*]);
    };

    // Only thirteen expanded round keys are needed, so only do one for the final round.
    ( $rk:ident => [$i:expr $(,)*] ) => {
        expand128!($rk[2*$i], $rk[2*$i+1], $rk[2*$i+2], splat_rot_sub_word_3, RCON[$i]);
    };
}

fn expand_key_128(key: &[u8; 16], round_keys: &mut [RoundKey; 11]) {
    round_keys[0] = Block::try_from(&key[..16]).unwrap();

    expand128!(round_keys => [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
}

#[allow(const_err)]
fn expand_key_192(key: &[u8; 24], round_keys: &mut [RoundKey; 13]) {
    round_keys[0] = Block::try_from(&key[..16]).unwrap();
    let tmp = Block::try_from(&key[8..24]).unwrap();
    round_keys[1] = op!(tmp >> (2 * COL_SHIFT));

    expand192!(round_keys => [0, 1, 2, 3]);
}

fn expand_key_256(key: &[u8; 32], round_keys: &mut [RoundKey; 15]) {
    round_keys[0] = Block::try_from(&key[..16]).unwrap();
    round_keys[1] = Block::try_from(&key[16..32]).unwrap();

    expand256!(round_keys => [0, 1, 2, 3, 4, 5, 6]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_sum() {
        let block = block_from_cols!(1, 2, 4, 2);
        assert_eq!(aes::Block::from(partial_sum_words(block)), aes::Block::from(block_from_cols!(1, 3, 7, 5)));
    }
}
