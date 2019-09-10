use core::mem::size_of;

pub const LINUX_GETCPU_H: i32 = 1;

/// Cache for getcpu() to speed it up. Results might be a short time
/// out of date, but will be faster.
///
/// User programs should not refer to the contents of this structure.
/// I repeat they should not refer to it. If they do they will break
/// in future kernels.
/// It is only a private cache for vgetcpu(). It will change in future kernels.
/// The user program must store this information per thread (__thread)
/// If you want 100% accurate information pass NULL instead.
#[repr(C)]
pub struct getcpu_cache_t {
    pub blob: [usize; 128 / size_of::<usize>()],
}
