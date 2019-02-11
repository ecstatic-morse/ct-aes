#[cfg(test)]
pub struct ArrayIter<A>(A, usize);

#[cfg(test)]
impl<A> ArrayIter<A> {
    pub fn new(arr: A) -> Self {
        ArrayIter(arr, 0)
    }
}

#[cfg(test)]
impl<A> Iterator for ArrayIter<A>
    where A: AsRef<[u8]>
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let s = self.0.as_ref();
        if self.1 >= s.len() {
            return None;
        }

        let next = s[self.1];
        self.1 += 1;
        Some(next)
    }
}

macro_rules! slice_as_array_ref {
    ($s:expr, $len:expr) => {
        if $s.len() != $len {
            Err(())
        } else {
            Ok(unsafe {
                &*($s.as_ptr() as *const [_; $len])
            })
        }
    }
}

/// Generates a `u64` at compile time which contains a `kernel` repeated every `shift` bits.
//
// TODO: make this recursive or a loop once control flow is legal in `const fn`s.
pub const fn bitmask(kernel: u64, shift: usize) -> u64 {
    // assert!((8 * mem::size_of_val(kernel)) - kernel.count_leading_zeros() <= shift);

    macro_rules! shifts {
        ($kernel:expr, $shift:expr, [$( $mul:tt, )*]) => {
            $( ($kernel << (($mul * $shift) % 64)) )|*
        }
    }

    shifts!(kernel, shift, [
         0,  1,  2,  3,  4,  5,  6,  7,
         8,  9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31,
        32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47,
        48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63,
    ])
}

/// Creates a new array containing the results of calling `$fn` on elements of `$arr`.
//
// TODO(#52000): This should become a `const fn` when binding, loops and generics are allowed.
macro_rules! const_map {
    ($fn:path => $arr:path [$( $idx:expr ),* $(,)*]) => {
        [ $( $fn($arr[$idx]) ),* ]
    };
}

/// Reverse a series of expressions.
macro_rules! reverse {
    ([] $($reversed:expr;)*) => {
        $( $reversed; )*
    };
    ([$head:expr; $($tail:expr;)*] $($reversed:expr;)*) => {
        reverse!([$($tail;)*] $head; $($reversed;)*)
    };
    ($($exprs:expr;)*) => {
        reverse!([$($exprs;)*])
    };
}

/// This macro defines the inverse of a function which is comprised exclusively of involutions.
///
/// Several useful functions in this library can be written as a sequence of expressions which are
/// their own inverse (e.g. `mem::swap`). Such a function is called an involution.
/// To invert a series of involutions, we can apply the same operations in reverse order.
macro_rules! define_function_of_involutions_with_inverse {
    ( $(
            #[inverse = $inverse:ident]
            $vis:vis fn $fn:ident ($($args:tt)*) {
                $( $expr:expr; )*
            }
    );* $(;)*) => {
        $(
            $vis fn $fn($($args)*) {
                $( $expr; )*
            }

            $vis fn $inverse($($args)*) {
                reverse!{ $( $expr; )* }
            }
        )*
    };
}

#[cfg(test)]
pub mod test {
    use std::io::Read;

    use try_from::TryFrom;

    use crate::aes::{self, ops::*};

    /// A wrapper around a source of entropy which implements `std::io::Read`.
    #[derive(Debug)]
    pub struct RngReadAdapter<R>(pub R);

    impl Default for RngReadAdapter<rand::rngs::ThreadRng> {
        fn default() -> Self {
            RngReadAdapter(rand::thread_rng())
        }
    }

    impl<R> std::io::Read for RngReadAdapter<R>
        where R: rand::Rng
    {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.fill(buf);
            Ok(buf.len())
        }
    }

    /// A function and its inverse.
    pub struct RoundTrip<B> {
        func: fn(&mut B),
        inv: fn(&mut B),
    }

    impl<B> RoundTrip<B> {
        pub fn shift_rows() -> Self where B: ShiftRows {
            RoundTrip {
                func: B::shift_rows,
                inv: B::inv_shift_rows,
            }
        }

        pub fn mix_columns() -> Self where B: MixColumns {
            RoundTrip {
                func: B::mix_columns,
                inv: B::inv_mix_columns,
            }
        }

        pub fn sub_bytes() -> Self where B: SubBytes {
            RoundTrip {
                func: B::sub_bytes,
                inv: B::inv_sub_bytes,
            }
        }
    }

    impl<B> RoundTrip<B>
        where B: Copy + for<'a> TryFrom<&'a [u8]> + IntoIterator<Item = u8>,
    {
        /// Asserts that `self.func(input) == output` and `self.inv(output) == input`.
        pub fn known_answer_test(&self, input: &[u8], num_blocks: usize, output: &[u8]) {
            assert!(input.len() % (num_blocks * aes::BLOCK_LEN) == 0);
            assert_eq!(input.len(), output.len());

            let chunks = input.chunks(aes::BLOCK_LEN)
                .zip(output.chunks(aes::BLOCK_LEN));

            for (input, output) in chunks {
                let len = input.len();
                let mut block = B::try_from(input).ok().unwrap();

                (self.func)(&mut block);
                let actual: Vec<u8> = block.into_iter().collect();
                assert_eq!(output, &actual[..len]);

                (self.inv)(&mut block);
                let actual: Vec<u8> = block.into_iter().collect();
                assert_eq!(input, &actual[..len]);
            }
        }

        /// Asserts that `self.func(input) == simple.func(input)` and `self.inv(input) ==
        /// simple.inv(input)`.
        pub fn comparison_test(&self,
                               simple: RoundTrip<aes::Block>,
                               mut input: impl Read,
                               num_blocks: usize)
        {
            let test = |dut: &mut B,
                        blocks: &mut [aes::Block],
                        test_fn: fn(&mut B),
                        simple_fn: fn(&mut aes::Block)| {
                test_fn(dut);
                let actual: Vec<u8> = dut.into_iter().collect();

                let it = actual.chunks_exact(aes::BLOCK_LEN)
                    .zip(blocks.iter_mut());

                for (actual, block) in it {
                    simple_fn(block);
                    assert_eq!(block.as_ref(), actual);
                }
            };

            let mut buf = vec![0; num_blocks * aes::BLOCK_LEN];

            while let Ok(()) = input.read_exact(&mut buf) {
                let mut dut = B::try_from(&buf).ok().unwrap();

                let mut simple_blocks: Vec<_> = buf.chunks_exact(aes::BLOCK_LEN)
                    .map(|b| aes::Block::try_from(&b).unwrap())
                    .collect();

                test(&mut dut, &mut simple_blocks, self.func, simple.func);
                test(&mut dut, &mut simple_blocks, self.inv, simple.inv);
            }
        }
    }
}

