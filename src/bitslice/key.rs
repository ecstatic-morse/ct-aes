use crate::ParallelBlockCipher;
use crate::aes::{self, key, Key};
use crate::word::MachineWord as Word;
use super::bitslice::{Bitslice, RoundKey};

const RCON: [RoundKey; 10]
    = const_map!(RoundKey::from_rc => aes::key::ROUND_CONSTANTS[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

/// The key schedule for bitsliced AES.
pub type Schedule = key::Schedule<Bitslice>;

impl From<Key<'_>> for Schedule {
    fn from(key: Key<'_>) -> Self {
        let mut sched = Schedule::new(key);
        let round_keys = sched.as_mut_slice();

        // 0..N
        for (i, key) in key.as_slice().chunks(aes::BLOCK_LEN).enumerate() {
            let rk = RoundKey::from_key(key);
            round_keys[i] = rk;
        }

        // N..(4*rk)
        let n = key.len() / 4;
        for i in n..(4 * key.num_round_keys()) {
            let mut a = sched.word(i - 1);
            match i % n {
                0 => {
                    a.rot_word();
                    a.sub_word();
                    a ^= RCON[(i / n) - 1];
                }

                4 if n > 6 => {
                    a.sub_word();
                }

                _ => (),
            }

            sched.set_word(i, a ^ sched.word(i - n));
        }

        sched
    }
}

impl ParallelBlockCipher for Schedule {
    const PARALLEL_BLOCKS: usize = Bitslice::<Word>::num_blocks();
}

impl Schedule {
    /// Returns a `RoundKey` containing the `n`-th word in the key schedule as
    /// its first col.
    fn word(&self, n: usize) -> RoundKey {
        let rk = self.as_slice()[n / 4];
        let col = n % 4;

        let mut word = RoundKey::default();
        for (&rk, w) in rk.iter().zip(word.iter_mut()) {
            *w |= (rk >> (col * Bitslice::<Word>::col_shift())) & Bitslice::<Word>::first_col();
        }

        word
    }

    /// Sets the `n`-th word in the key schedule.
    fn set_word(&mut self, n: usize, word: RoundKey) {
        // debug_assert_eq!(0, word & !FIRST_ROW);
        let rk = &mut self.as_mut_slice()[n / 4];
        let col = n % 4;

        for (rk, &w) in rk.iter_mut().zip(word.iter()) {
            *rk &= !Bitslice::<Word>::nth_col_mask(col);
            *rk |= (w << (col * Bitslice::<Word>::col_shift())) & Bitslice::<Word>::nth_col_mask(col);
        }
    }
}
