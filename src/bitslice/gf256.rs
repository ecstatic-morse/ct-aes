include!(concat!(env!("OUT_DIR"), "/gf256.rs"));

/// Evaluates the four-term polynomials used in AES `MixColumns` with the given coefficients.
macro_rules! gf_polyval4 {
    ($a:tt * $in:ident[0] ^ $b:tt * $_1:ident[1] ^ $c:tt * $_2:ident[2] ^ $d:tt * $_3:ident[3]) => {
        gf_polyval4!($in[0,1,2,3,4,5,6,7] => [$a, $b, $c, $d]);
    };

    ($in:ident[$($idx:tt),*] => [$a:tt, $b:tt, $c:tt, $d:tt]) => {
        [ $(
            gfmul!($idx; $a*$in)
                ^ gfmul!($idx; $b*$in).rotate_right((1 * Self::row_shift()) as u32)
                ^ gfmul!($idx; $c*$in).rotate_right((2 * Self::row_shift()) as u32)
                ^ gfmul!($idx; $d*$in).rotate_right((3 * Self::row_shift()) as u32)
        ),* ]
    };
}

