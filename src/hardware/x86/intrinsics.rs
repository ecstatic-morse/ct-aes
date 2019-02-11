//! Some x86{,_64} intrinsics take an immediate operand which must be const. However, there is no
//! way to declare that a function argument is const. This is discussed further [here][const-args].
//! As a result, some intrinsics are exposed as macros.
//!
//! [const-args]: https://github.com/rust-lang/rust/issues/47980

pub const fn permute_col_mask(ws: [u8; 4]) -> u8 {
    (ws[0] & 0x3) 
        | ((ws[1] & 0x3) << 2)
        | ((ws[2] & 0x3) << 4)
        | ((ws[3] & 0x3) << 6)
}

macro_rules! pshufd {
    ( $a:expr, $imm:expr ) => {
        unsafe {
            use $crate::hardware::x86::intrinsics::permute_col_mask;
            Block(simd::_mm_shuffle_epi32($a.0, permute_col_mask($imm) as i32))
        }
    }
}

/// `shufps` is defined on __m128 (4xf32) but not __m128i (4xu32). However, it comes in handy for
/// some permutations.
macro_rules! shufps {
    ( $a:expr, $b:expr, $imm:expr ) => {
        unsafe {
            use $crate::hardware::x86::intrinsics::permute_col_mask;
            let a: simd::__m128 = mem::transmute($a.0);
            let b: simd::__m128 = mem::transmute($b.0);
            let floats = simd::_mm_shuffle_ps(a, b, permute_col_mask($imm) as u32);
            Block(mem::transmute(floats))
        }
    }
}

macro_rules! keygenassist {
    ( $a:expr, $rc:expr ) => {
        unsafe {
            Block(simd::_mm_aeskeygenassist_si128($a.0, $rc))
        }
    }
}

/// Arithmetic operations with an immediate as an operand.
macro_rules! op {
    ( $a:ident << $imm:expr ) => {
        unsafe {
            Block(simd::_mm_slli_si128($a.0, $imm as i32))
        }
    };

    ( $a:ident >> $imm:tt ) => {
        unsafe {
            Block(simd::_mm_srli_si128($a.0, $imm as i32))
        }
    };
}

