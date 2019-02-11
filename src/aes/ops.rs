/// A data type which stores some number of AES blocks.
pub trait BlockRepr {
    /// The number of blocks stored.
    const NUM_BLOCKS: usize;

    /// Writes the stored blocks to the given slice. `dst.len()` must be at least `Self::NUM_BLOCKS
    /// * aes::BLOCK_LEN`.
    fn copy_to_slice(&self, dst: &mut [u8]);
}

/// An AES implementation.
pub trait Aes: Sized + Copy + AddRoundKey {
    /// Performs a normal round of AES encryption.
    fn encrypt_round(&mut self, rk: &Self::RoundKey);

    /// Performs the final round of AES encryption (no `MixColumns`).
    fn encrypt_round_last(&mut self, rk: &Self::RoundKey);

    /// Performs a normal round of AES decryption.
    fn decrypt_round(&mut self, rk: &Self::RoundKey);

    /// Performs the final round of AES decryption (no `MixColumns`).
    fn decrypt_round_last(&mut self, rk: &Self::RoundKey);

    /// Performs an AES encryption in-place.
    fn encrypt(&mut self, round_keys: &[Self::RoundKey]) {
        let rounds = round_keys.len();
        assert!(rounds == 11 || rounds == 13 || rounds == 15);

        self.add_round_key(round_keys.first().unwrap());

        for key in &round_keys[1..rounds-1] {
            self.encrypt_round(key);
        }

        self.encrypt_round_last(round_keys.last().unwrap());
    }

    /// Performs an AES decryption in-place.
    fn decrypt(&mut self, round_keys: &[Self::RoundKey]) {
        let rounds = round_keys.len();
        assert!(rounds == 11 || rounds == 13 || rounds == 15);

        self.add_round_key(round_keys.last().unwrap());

        for key in round_keys[1..rounds-1].iter().rev() {
            self.decrypt_round(key);
        }

        self.decrypt_round_last(round_keys.first().unwrap());
    }
}

impl<T> Aes for T
    where T: Copy + ShiftRows + MixColumns + SubBytes + AddRoundKey
{
    fn encrypt_round(&mut self, rk: &Self::RoundKey) {
        self.sub_bytes();
        self.shift_rows();
        self.mix_columns();
        self.add_round_key(rk);
    }

    fn encrypt_round_last(&mut self, rk: &Self::RoundKey) {
        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(rk);
    }

    fn decrypt_round(&mut self, rk: &Self::RoundKey) {
        self.inv_shift_rows();
        self.inv_sub_bytes();
        self.add_round_key(rk);
        self.inv_mix_columns();
    }

    fn decrypt_round_last(&mut self, rk: &Self::RoundKey) {
        self.inv_shift_rows();
        self.inv_sub_bytes();
        self.add_round_key(rk);
    }
}

pub trait ShiftRows {
    /// Executes `ShiftRows` in-place.
    fn shift_rows(&mut self);

    /// Executes `InvShiftRows` in-place.
    fn inv_shift_rows(&mut self);
}

pub trait MixColumns {
    /// Executes `MixColumns` in-place.
    ///
    /// ```text
    /// c = 3•x³ ⊕  x² ⊕  x ⊕ 2
    ///
    /// c[i] = 2 • b[i]
    ///      ⊕ 3 • b[i+1]
    ///      ⊕     b[i+2]
    ///      ⊕     b[i+3]
    /// ```
    fn mix_columns(&mut self);

    /// Executes `InvMixColumns` in-place.
    ///
    /// ```text
    /// c[i] = 14 • b[i]   // 0b1110
    ///      ⊕ 11 • b[i+1] // 0b1011
    ///      ⊕ 13 • b[i+2] // 0b1101
    ///      ⊕  9 • b[i+3] // 0b1001
    /// ```
    fn inv_mix_columns(&mut self);
}

pub trait SubBytes {
    /// Executes `SubBytes` in-place.
    fn sub_bytes(&mut self);

    /// Executes `InvSubBytes` in-place.
    fn inv_sub_bytes(&mut self);
}


pub trait AddRoundKey {
    type RoundKey;

    fn add_round_key(&mut self, rk: &Self::RoundKey);
}
