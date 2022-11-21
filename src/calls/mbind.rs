/// Set memory policy for a memory range.
pub unsafe fn mbind(
    start: usize,
    len: usize,
    mode: i32,
    nmask: *const usize,
    maxnode: usize,
    flags: i32,
) -> Result<(), Errno> {
    let mode = mode as usize;
    let nmask = nmask as usize;
    let flags = flags as usize;
    syscall6(SYS_MBIND, start, len, mode, nmask, maxnode, flags).map(drop)
}
