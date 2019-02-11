//! Detects the size of a general-purpose register on the target architecture.

use cfg_if::cfg_if;

/// The unsigned integer type with the same size as a hardware register.
cfg_if! {
    // On some esoteric targets like x32, the size of a pointer is less than the size of a
    // register. Check `target_arch` first to provide a more reliable indicator of register size.
    if #[cfg(any(target_arch = "aarch64",
                 target_arch = "mips64", target_arch = "mips64el",
                 target_arch = "powerpc64", target_arch = "powerpc64le",
                 target_arch = "sparc64",
                 target_arch = "x86_64"))]
    {
        pub type MachineWord = u64;
    } else if #[cfg(target_pointer_width = "64")] {
        pub type MachineWord = u64;
    } else if #[cfg(target_pointer_width = "32")] {
        pub type MachineWord = u32;
    } else {
        pub type MachineWord = u16;
    }
}
