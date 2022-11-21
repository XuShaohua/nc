/// Synchronize a file with memory map.
pub unsafe fn msync(addr: usize, len: size_t, flags: i32) -> Result<(), Errno> {
    let flags = flags as usize;
    syscall3(SYS_MSYNC, addr, len, flags).map(drop)
}
