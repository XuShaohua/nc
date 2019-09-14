/// kexec system call -  It loads the new kernel to boot into.
/// kexec does not sync, or unmount filesystems so if you need
/// that to happen you need to do that yourself.

/// kexec flags for different usage scenarios
pub const KEXEC_ON_CRASH: i32 = 0x00000001;
pub const KEXEC_PRESERVE_CONTEXT: i32 = 0x00000002;
pub const KEXEC_ARCH_MASK: i32 = 0xffff0000;

/// Kexec file load interface flags.
/// KEXEC_FILE_UNLOAD : Unload already loaded kexec/kdump image.
/// KEXEC_FILE_ON_CRASH : Load/unload operation belongs to kdump image.
/// KEXEC_FILE_NO_INITRAMFS : No initramfs is being loaded. Ignore the initrd
/// fd field.
pub const KEXEC_FILE_UNLOAD: i32 = 0x00000001;
pub const KEXEC_FILE_ON_CRASH: i32 = 0x00000002;
pub const KEXEC_FILE_NO_INITRAMFS: i32 = 0x00000004;

/// These values match the ELF architecture values.
/// Unless there is a good reason that should continue to be the case.
pub const KEXEC_ARCH_DEFAULT: i32 = (0 << 16);
pub const KEXEC_ARCH_386: i32 = (3 << 16);
pub const KEXEC_ARCH_68K: i32 = (4 << 16);
pub const KEXEC_ARCH_X86_64: i32 = (62 << 16);
pub const KEXEC_ARCH_PPC: i32 = (20 << 16);
pub const KEXEC_ARCH_PPC64: i32 = (21 << 16);
pub const KEXEC_ARCH_IA_64: i32 = (50 << 16);
pub const KEXEC_ARCH_ARM: i32 = (40 << 16);
pub const KEXEC_ARCH_S390: i32 = (22 << 16);
pub const KEXEC_ARCH_SH: i32 = (42 << 16);
pub const KEXEC_ARCH_MIPS_LE: i32 = (10 << 16);
pub const KEXEC_ARCH_MIPS: i32 = (8 << 16);
pub const KEXEC_ARCH_AARCH64: i32 = (183 << 16);

/// The artificial cap on the number of segments passed to kexec_load.
pub const KEXEC_SEGMENT_MAX: i32 = 16;

/// This structure is used to hold the arguments that are used when
/// loading  kernel binaries.
#[repr(C)]
pub struct kexec_segment_t {
    pub buf: usize,
    pub bufsz: size_t,
    pub mem: usize,
    pub memsz: size_t,
}
