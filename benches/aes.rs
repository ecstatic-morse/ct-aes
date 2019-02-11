#![feature(test)]

extern crate test;
extern crate ct_aes;

use ct_aes as aes;

use self::aes::{Key, BlockCipher};

fn block_cipher<K>(b: &mut test::Bencher)
    where K: BlockCipher + for<'a> From<Key<'a>>
{
    let mut data = [0u8; 8192];
    for (i, s) in data.chunks_exact_mut(2).enumerate() {
        s[0] = (i % 0xff) as u8;
        s[1] = (i / 0xff) as u8;
    }

    let key: K = Key::from_bytes(&[
        0xff, 0xef, 0xdf, 0xcf,
        0xb8, 0xa8, 0x98, 0x88,
        0x7f, 0x6f, 0x5f, 0x4f,
        0x30, 0x20, 0x10, 0x00,
    ]).unwrap().into();

    b.iter(|| {
        let mut data = test::black_box(&mut data[..]);
        while !data.is_empty() {
            let adv = key.encrypt_blocks(data);
            data = &mut data[adv..];
        }
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[bench]
fn x86(b: &mut test::Bencher) {
    block_cipher::<aes::hardware::x86::Schedule>(b);
}

#[bench]
fn bitslice(b: &mut test::Bencher) {
    block_cipher::<aes::bitslice::Schedule>(b);
}
