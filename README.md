**This library is a WORK IN PROGRESS. It is INSECURE and should not be used by ANYONE.**

# Timing-attack Resistant AES Encryption

This crate implements the AES block cipher using methods which are resistant to
timing attacks. The fastest, non-parallel, software algorithm uses a 4kB lookup
table which is vulnerable to [cache-based side-channel attacks][t-table]. In
practice, this is not a major security vulnerability since most widely-used
platforms use custom assembly routines for encryption.  However, it may be
desirable to have a reasonably performant, cross-platform, timing attack
resistant AES implementation for platforms without dedicated AES or SIMD
instructions.

Note that this crate only implements the AES block cipher, which is suitable
for encrypting exactly 16 bytes of data. If you wish to encrypt data streams,
you must implement your own [block cipher mode][]; this crate does not
provide one.

[block cipher mode]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Common_modes
[t-table]: https://access.redhat.com/blogs/766093/posts/1976303

# Preserving Timing Properties Across Compiler Optimizations

Modern optimizing compilers do not preserve the semantics of your source code
when compiling to machine code. They guarantee only that the observable side
effects will be the same at [certain times during program
execution][seq-point]. In most cases, this is a good thing: it allows our
highly-abstracted code to be compiled into a performant binary.

[seq-point]: https://en.wikipedia.org/wiki/Sequence_point

However, most compilers do not treat instruction timing or cache modification
as observable side effects. Indeed, optimizing a program without changing
its control flow or cache access patterns would be a difficult feat! For this
reason, most timing-critical routines are written in assembly language,
guaranteeing that they appear verbatim in the generated executable.

Hand-coding assembly is costly in terms of developer time,
especially for less commonly used architectures, so writing a single
implementation in a high-level language which works cross-platform would be
beneficial. However, it requires careful auditing of both the source code and
generated assembly, along with some clever tricks to ensure that your carefully
designed, timing-attack resistant library is not optimized into a
vulnerable state when actually used. At the moment, this library does not take
any of these measures, and *should not be used* except perhaps as an intelligible
reference for assembly implementations. Before it can be used as is, I must do
the following:

- [ ] Pessimize the local optimizer using intrinsics like `test::black_box`.
- [ ] Put timing critical code behind an FFI barrier to make it opaque to
  whole-program optimization .
- [ ] Audit the generated assembly to ensure that the tricks from the previous
  two sections had the desired effect.

The last step is the most painful, but [recent developments][] in automated
verification may make it feasible. The long-term goal for this library is to be
a test case for such verification, and work on this step will take priority
over the other two.

[recent developments]: https://www.usenix.org/system/files/conference/usenixsecurity16/sec16_paper_almeida.pdf

# Implementation

We use an implementation technique called ["bitslicing"][] to implement
constant-time AES in a cross-platform way [1].

["bitslicing"]: https://en.wikipedia.org/wiki/Bit_slicing

The main obstacle to a constant-time AES implementation is the [Rijndael
S-box][], which requires us to perform inversion in GF(2⁸).
This is computationally difficult, so practical implementations use a lookup
table. Since this lookup table is only 256 bytes (4 cache lines) large, it is
[likely resistant to cache-timing attacks][t-table]. However, we must still
perform multiplication in GF(2^8) during `MixColumns`. Fast software
implementations use a combined lookup table for both steps, meaning all
computations in finite field are performed ahead of time. We would like
something that is more performant than the naive AES implementation, but
doesn't use a lookup table.

[Rijndael S-box]: https://en.wikipedia.org/wiki/Rijndael_S-box

The bitslicing paradigm is to emulate digital logic using general purpose
registers. Each register is treated as a SIMD register whose elements are 1 bit
wide. By splitting each byte of data into individual bits and packing those
bits together in registers, we can perform fundamental logic operations (AND,
OR, etc.) in parallel. A significant amount of work has been done to realize
efficient AES implementations in hardware; we can leverage this for our
bitsliced software implementation. Moreover, since we can perform our logic
operations in parallel, we get performance linear in the size of a machine
word, as long as we work in a cipher mode that allows us to process blocks in
parallel.

OpenSSL currently has a bitsliced AES implementation for certain platforms
which uses SIMD registers and which can process up to 16 blocks in parallel. In
doing so, it achieves speeds better than the T-table-based implementation.
Since the purpose of this crate is to be cross-platform, the maximum
parallelism is only 64 bits (4 AES blocks) at a time. This will be extended
when a suitable cross-platform SIMD library exists for rust.

# References

[1] Emilia Käsper and Peter Schwabe. 2009. Faster and Timing-Attack Resistant
AES-GCM. In Proceedings of the 11th International Workshop on Cryptographic
Hardware and Embedded Systems (CHES '09), Christophe Clavier and Kris Gaj
(Eds.). Springer-Verlag, Berlin, Heidelberg, 1-17.
DOI=http://dx.doi.org/10.1007/978-3-642-04138-9_1


