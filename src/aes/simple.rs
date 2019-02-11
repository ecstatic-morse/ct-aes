//! An unoptimized implementation of AES which uses a 256-byte lookup table.

use gf256::Element;
use try_from::TryFrom;

use crate::BlockCipher;
use crate::aes::{self, Block, ops::*, Key, SBOX, INV_SBOX};

impl IntoIterator for Block {
    type Item = u8;
    type IntoIter = crate::util::ArrayIter<[u8; aes::BLOCK_LEN]>;

    fn into_iter(self) -> Self::IntoIter {
        crate::util::ArrayIter::new(self.into())
    }
}

impl SubBytes for Block {
    fn sub_bytes(&mut self) {
        let Block(block) = self;
        for byte in block {
            *byte = SBOX[*byte as usize];
        }
    }

    fn inv_sub_bytes(&mut self) {
        let Block(block) = self;
        for byte in block {
            *byte = INV_SBOX[*byte as usize];
        }
    }
}

impl ShiftRows for Block {
    define_function_of_involutions_with_inverse! {
        #[inverse = inv_shift_rows]
        fn shift_rows(&mut self) {
            // Row 1
            self.0.swap(1, 5);
            self.0.swap(5, 9);
            self.0.swap(9, 13);

            // Row 2
            self.0.swap(2, 10);
            self.0.swap(6, 14);

            // Row 3
            self.0.swap(11, 15);
            self.0.swap(7, 11);
            self.0.swap(3, 7);
        }
    }
}

impl MixColumns for Block {
    fn mix_columns(&mut self) {
        let elem = |r, c| Element(self[(r % 4, c)]);

        let mut tmp: Block = Block::default();
        for col in 0..4 {
            for row in 0..4 {
                let el = Element(2) * elem(row,   col)
                       + Element(3) * elem(row+1, col)
                       + Element(1) * elem(row+2, col)
                       + Element(1) * elem(row+3, col);

                tmp[(row, col)] = el.0;
            }
        }

        *self = tmp;
    }

    fn inv_mix_columns(&mut self) {
        let elem = |r, c| Element(self[(r % 4, c)]);

        let mut tmp = Block::default();
        for col in 0..4 {
            for row in 0..4 {
                let el = Element(14) * elem(row,   col)
                       + Element(11) * elem(row+1, col)
                       + Element(13) * elem(row+2, col)
                       + Element(9)  * elem(row+3, col);

                tmp[(row, col)] = el.0;
            }
        }

        *self = tmp;
    }
}

impl AddRoundKey for Block {
    type RoundKey = Self;

    fn add_round_key(&mut self, rk: &Self::RoundKey) {
        for (a, b) in self.iter_mut().zip(rk.iter()) {
            *a ^= b;
        }
    }
}

type Schedule = aes::key::Schedule<Block>;

impl Schedule {
    fn word(&self, n: usize) -> u32 {
        let Block(rk) = self.as_slice()[n / 4];
        let i = 4 * (n % 4);
        u32::from_be_bytes(*slice_as_array_ref!(rk[i..i+4], 4).unwrap())
    }

    fn set_word(&mut self, n: usize, word: u32) {
        let Block(rk) = &mut self.as_mut_slice()[n / 4];
        let i = 4 * (n % 4);
        rk[i..i+4].copy_from_slice(&word.to_be_bytes());
    }
}

fn sub_word(word: u32) -> u32 {
    let mut bytes = word.to_ne_bytes();
    for byte in &mut bytes {
        *byte = SBOX[*byte as usize];
    }

    u32::from_ne_bytes(bytes)
}

impl From<Key<'_>> for Schedule {
    fn from(key: Key<'_>) -> Self {
        let mut sched = Schedule::new(key);

        // 0..N
        let rks = sched.as_mut_slice();
        for (i, key) in key.as_slice().chunks(aes::BLOCK_LEN).enumerate() {
            let Block(block) = &mut rks[i];
            block[..key.len()].copy_from_slice(key);
        }


        // N..(4*rk)
        let n = key.len() / 4;
        for i in n..(4 * key.num_round_keys()) {
            let mut a = sched.word(i - 1);
            match i % n {
                0 => {
                    a = a.rotate_left(8);
                    a = sub_word(a);
                    a ^= (aes::key::ROUND_CONSTANTS[(i / n) - 1] as u32).to_be();
                }

                4 if n > 6 => {
                    a = sub_word(a);
                }

                _ => (),
            }

            sched.set_word(i, a ^ sched.word(i - n));
        }


        sched
    }
}

impl BlockCipher for Schedule {
    fn encrypt_blocks(&self, bytes: &mut [u8]) -> usize {
        let mut block = Block::try_from(&bytes[..aes::BLOCK_LEN]).unwrap();
        block.encrypt(self.as_slice());
        let block: [u8; 16] = block.into();
        bytes[..aes::BLOCK_LEN].copy_from_slice(&block[..aes::BLOCK_LEN]);
        16
    }

    fn decrypt_blocks(&self, bytes: &mut [u8]) -> usize {
        let mut block = Block::try_from(&bytes[..aes::BLOCK_LEN]).unwrap();
        block.decrypt(self.as_slice());
        let block: [u8; 16] = block.into();
        bytes[..aes::BLOCK_LEN].copy_from_slice(&block[..aes::BLOCK_LEN]);
        16
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::aes::{self, Key};
    use crate::util::test::RoundTrip;
    use super::*;

    pub fn hex(s: &str) -> impl '_ + Iterator<Item = u8> {
        let mut state = None;

        s.chars()
            .filter(|c| !c.is_whitespace())
            .filter_map(move |c| {
                let nibble = u8::from_str_radix(&c.to_string(), 16).unwrap();
                if let Some(upper) = state.take() {
                    Some(upper << 4 | nibble)
                } else {
                    state = Some(nibble);
                    None
                }
            })
    }

    pub fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex(s).collect()
    }

    #[test]
    fn key_expansion() {
        const EXPANDED_KEYS: &[&str] = &[
             // 128 bit
            "2b7e1516 28aed2a6 abf71588 09cf4f3c  a0fafe17 88542cb1 23a33939 2a6c7605
             f2c295f2 7a96b943 5935807a 7359f67f  3d80477d 4716fe3e 1e237e44 6d7a883b
             ef44a541 a8525b7f b671253b db0bad00  d4d1c6f8 7c839d87 caf2b8bc 11f915bc
             6d88a37a 110b3efd dbf98641 ca0093fd  4e54f70e 5f5fc9f3 84a64fb2 4ea6dc4f
             ead27321 b58dbad2 312bf560 7f8d292f  ac7766f3 19fadc21 28d12941 575c006e
             d014f9a8 c9ee2589 e13f0cc8 b6630ca6",

             // 192 bit
            "8e73b0f7 da0e6452 c810f32b 809079e5  62f8ead2 522c6b7b fe0c91f7 2402f5a5
             ec12068e 6c827f6b 0e7a95b9 5c56fec2  4db7b4bd 69b54118 85a74796 e92538fd
             e75fad44 bb095386 485af057 21efb14f  a448f6d9 4d6dce24 aa326360 113b30e6
             a25e7ed5 83b1cf9a 27f93943 6a94f767  c0a69407 d19da4e1 ec1786eb 6fa64971
             485f7032 22cb8755 e26d1352 33f0b7b3  40beeb28 2f18a259 6747d26b 458c553e
             a7e1466c 9411f1df 821f750a ad07d753  ca400538 8fcc5006 282d166a bc3ce7b5
             e98ba06f 448c773c 8ecc7204 01002202",

             // 256 bit
            "603deb10 15ca71be 2b73aef0 857d7781  1f352c07 3b6108d7 2d9810a3 0914dff4
             9ba35411 8e6925af a51a8b5f 2067fcde  a8b09c1a 93d194cd be49846e b75d5b9a
             d59aecb8 5bf3c917 fee94248 de8ebe96  b5a9328a 2678a647 98312229 2f6c79b3
             812c81ad dadf48ba 24360af2 fab8b464  98c5bfc9 bebd198e 268c3ba7 09e04214
             68007bac b2df3316 96e939e4 6c518d80  c814e204 76a9fb8a 5025c02d 59c58239
             de136967 6ccc5a71 fa256395 9674ee15  5886ca5d 2e2f31d7 7e0af1fa 27cf73c3
             749c47ab 18501dda e2757e4f 7401905a  cafaaae3 e4d59b34 9adf6ace bd10190d
             fe4890d1 e6188d0b 046df344 706c631e",
        ];

        for key_sched in EXPANDED_KEYS {
            let bytes = hex_to_bytes(key_sched);
            let key_len = match bytes.len() / 16 {
                11 => 16,
                13 => 24,
                15 => 32,
                _ => unreachable!(),
            };

            // Get the key from the first few round keys.
            let key: aes::key::Schedule<Block>
                = Key::from_bytes(&bytes[..key_len]).unwrap().into();

            for (actual, expected) in key.as_slice().iter().zip(bytes.chunks_exact(aes::BLOCK_LEN)) {
                let actual: aes::Block = (*actual).into();
                let expected = aes::Block::try_from(expected).unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    pub fn round_trip() {
        struct Kat<'a> {
            key: &'a str,
            plain: &'a str,
            cipher: &'a str,
        }

        const KNOWN_ANSWER_TESTS: &[Kat] = &[
            Kat {
                key:    "000102030405060708090a0b0c0d0e0f",
                plain:  "00112233445566778899aabbccddeeff",
                cipher: "69c4e0d86a7b0430d8cdb78070b4c55a",
            },
            Kat {
                key:    "000102030405060708090a0b0c0d0e0f1011121314151617",
                plain:  "00112233445566778899aabbccddeeff",
                cipher: "dda97ca4864cdfe06eaf70a0ec0d7191",
            },
            Kat {
                key:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                plain:  "00112233445566778899aabbccddeeff",
                cipher: "8ea2b7ca516745bfeafc49904b496089",
            },
        ];

        for Kat { key, plain, cipher } in KNOWN_ANSWER_TESTS {
            let key = hex_to_bytes(key);
            let key: Schedule = Key::from_bytes(&key).unwrap().into();

            let plain = hex_to_bytes(plain);
            let cipher = hex_to_bytes(cipher);
            let mut buf = plain.clone();

            key.encrypt_blocks(&mut buf);
            assert_eq!(buf, cipher);

            key.decrypt_blocks(&mut buf);
            assert_eq!(buf, plain);
        }
    }

    #[test]
    fn shift_rows() {
        let input = Block::from_row_major([
             0,  1,  2,  3,
             4,  5,  6,  7,
             8,  9, 10, 11,
            12, 13, 14, 15,
        ]);

        let output = Block::from_row_major([
             0,  1,  2,  3,
             5,  6,  7,  4, // << 1
            10, 11,  8,  9, // << 2
            15, 12, 13, 14, // << 3
        ]);

        RoundTrip::<Block>::shift_rows()
            .known_answer_test(input.as_ref(), 1, output.as_ref());
    }

    #[test]
    /// From https://en.wikipedia.org/wiki/Rijndael_MixColumns#Test_vectors_for_MixColumn()
    fn mix_columns() {
        let input: &[u8] = &[
            0xdb, 0x13, 0x53, 0x45,
            0xf2, 0x0a, 0x22, 0x5c,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6,

            0xd4, 0xd4, 0xd4, 0xd5,
            0x2d, 0x26, 0x31, 0x4c,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let output: &[u8] = &[
            0x8e, 0x4d, 0xa1, 0xbc,
            0x9f, 0xdc, 0x58, 0x9d,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6,

            0xd5, 0xd5, 0xd7, 0xd6,
            0x4d, 0x7e, 0xbd, 0xf8,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        RoundTrip::<Block>::mix_columns()
            .known_answer_test(input.as_ref(), 1, output.as_ref());
    }

    #[test]
    fn sub_bytes() {
        let input: Vec<u8> = (0..=255).collect();
        let output: Vec<u8> = input
            .iter()
            .map(|&b| SBOX[b as usize])
            .collect();

        RoundTrip::<Block>::sub_bytes()
            .known_answer_test(input.as_ref(), 1, output.as_ref());
    }
}
