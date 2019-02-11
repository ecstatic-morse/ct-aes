use core::ops;
use core::marker::PhantomData;

use crate::{aes::{self, key}, BlockCipher};

pub trait Lane: Copy + Sized + ops::BitXorAssign {
    /// The number of `aes::Block`s per lane.
    const NUM_BLOCKS: usize;

    fn from_bytes(bytes: &[u8]) -> Self;
    fn copy_bytes_to(&self, out: &mut [u8]);

    fn encrypt_round(&mut self, rk: Self);
    fn encrypt_round_final(&mut self, rk: Self);
    fn decrypt_round(&mut self, rk: Self);
    fn decrypt_round_final(&mut self, rk: Self);
}

pub struct Interleave<L, N>(pub key::Schedule<L>, PhantomData<N>);

impl<L, N> From<key::Schedule<L>> for Interleave<L, N> {
    fn from(key: key::Schedule<L>) -> Self {
        Interleave(key, PhantomData)
    }
}

macro_rules! impl_interleave {
    ($( $A:ident($len:expr) => [$($i:tt),*] );* $(;)*) => {
        $(
            pub type $A<L> = Interleave<L, [u8; $len]>;

            impl<L> BlockCipher for $A<L>
                where L: Lane,
            {
                const BLOCKS: usize = L::NUM_BLOCKS * $len;

                fn encrypt_blocks(&self, bytes: &mut [u8]) {
                    let round_keys = self.0.as_slice();
                    let len = round_keys.len();

                    let mut blocks = [
                        $( L::from_bytes(&bytes[($i * L::NUM_BLOCKS * aes::BLOCK_LEN)..(($i+1) * L::NUM_BLOCKS * aes::BLOCK_LEN)]) ),*
                    ];

                    $( blocks[$i] ^= *round_keys.first().unwrap(); )*

                    for &rk in &round_keys[1..len-1] {
                        $( blocks[$i].encrypt_round(rk); )*
                    }

                    $( blocks[$i].encrypt_round_final(*round_keys.last().unwrap()); )*
                    $( blocks[$i].copy_bytes_to(&mut bytes[($i * L::NUM_BLOCKS * aes::BLOCK_LEN)..(($i+1) * L::NUM_BLOCKS * aes::BLOCK_LEN)]); )*
                }

                fn decrypt_blocks(&self, bytes: &mut [u8]) {
                    let round_keys = self.0.as_slice();
                    let len = round_keys.len();

                    let mut blocks = [
                        $( L::from_bytes(&bytes[($i * L::NUM_BLOCKS * aes::BLOCK_LEN)..(($i+1) * L::NUM_BLOCKS * aes::BLOCK_LEN)]) ),*
                    ];

                    $( blocks[$i] ^= *round_keys.last().unwrap(); )*

                    for &rk in round_keys[1..len-1].iter().rev() {
                        $( blocks[$i].decrypt_round(rk); )*
                    }

                    $( blocks[$i].decrypt_round_final(*round_keys.first().unwrap()); )*
                    $( blocks[$i].copy_bytes_to(&mut bytes[($i * L::NUM_BLOCKS * aes::BLOCK_LEN)..(($i+1) * L::NUM_BLOCKS * aes::BLOCK_LEN)]); )*
                }
            }
        )*
    }
}

impl_interleave! {
    Interleave1(1) => [0];
    Interleave2(2) => [0, 1];
    Interleave3(3) => [0, 1, 2];
    Interleave4(4) => [0, 1, 2, 3];
    Interleave6(6) => [0, 1, 2, 3, 4, 5];
    Interleave8(8) => [0, 1, 2, 3, 4, 5, 6, 7];
}
