//! Test encryption/decryption against OpenSSL for correctness.

use openssl::symm::{Cipher, Crypter, Mode};
use rand::RngCore;

use ct_aes as aes;

macro_rules! crypter {
    ($( $name:ident => $cipher:ident, $mode:ident );* $(;)?) => {
        $(
            fn $name(key: &[u8]) -> Crypter {
                let mut ret = Crypter::new(
                    Cipher::$cipher(),
                    Mode::$mode,
                    key,
                    None,
                ).unwrap();
                ret.pad(false);
                ret
            }
        )*
    }
}

crypter! {
    encrypt_128 => aes_128_ecb, Encrypt;
    // decrypt_128 => aes_128_ecb, Decrypt;
    encrypt_256 => aes_256_ecb, Encrypt;
    // decrypt_256 => aes_256_ecb, Decrypt;
}

fn encrypt_all_ct<T: aes::BlockCipher>(ct: &T, buf: &mut [u8]) {
    let mut cursor = buf;
    while !cursor.is_empty() {
        let adv = ct.encrypt_blocks(cursor);
        cursor = &mut cursor[adv..];
    }
}

fn decrypt_all_ct<T: aes::BlockCipher>(ct: &T, buf: &mut [u8]) {
    let mut cursor = buf;
    while !cursor.is_empty() {
        let adv = ct.decrypt_blocks(cursor);
        cursor = &mut cursor[adv..];
    }
}

fn encrypt_all_ssl(ssl: &mut Crypter, input: &[u8], output: &mut [u8]) {
    ssl.update(input, output).unwrap();
    ssl.finalize(output).unwrap();
}

macro_rules! suite {
    ($( $name:ident($len:expr) => $crypter:path, $ct_aes:path );* $(;)?) => {
        $(
            #[test]
            #[ignore]
            fn $name() {
                const KEY_LEN: usize = $len;

                let mut rng = rand::thread_rng();

                let mut key = vec![0; KEY_LEN];
                let mut input = vec![0; 8192];
                let mut ssl_output = vec![0; 8192 + 16]; // OpenSSL requires an extra block for possible padding
                let mut ct_output = vec![0; 8192];

                for _ in 0..4096 {
                    rng.fill_bytes(&mut key);
                    let mut ssl_enc = $crypter(&key);
                    let ct: $ct_aes = aes::Key::from_bytes(&key)
                        .unwrap()
                        .into();

                    rng.fill_bytes(&mut input);

                    // Encrypt with ct_aes
                    ct_output.copy_from_slice(&input);
                    encrypt_all_ct(&ct, &mut ct_output);

                    // Encrypt with ssl
                    encrypt_all_ssl(&mut ssl_enc, &input, &mut ssl_output);

                    // Compare outputs
                    assert_eq!(&ssl_output[..8192], &ct_output[..]);

                    // Test decryption
                    decrypt_all_ct(&ct, &mut ct_output);
                    assert_eq!(&input, &ct_output);
                }
            }
        )*
    }
}

suite! {
    compare_128_bitslice(16) => encrypt_128, aes::bitslice::Schedule;
    compare_256_bitslice(32) => encrypt_256, aes::bitslice::Schedule;
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
suite! {
    compare_128_x86_aesni(16) => encrypt_128, aes::hardware::x86::Schedule;
    compare_256_x86_aesni(32) => encrypt_256, aes::hardware::x86::Schedule;
}
